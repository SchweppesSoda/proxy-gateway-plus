#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# pdg_write_unit 必须原子: 生成函数不存在/失败/产出为空时, **一个字节都不许写进目标**。
#
# 为什么非要这条: 跨版本回滚会踩到它。机器跑 v1.5.12 执行 `pdg update` → 仓库已切到
# v1.6.x 并完成 sing-box→mihomo 迁移 → 后续校验门(doctor/nft/daemon-reload)失败 →
# **仍在内存里的旧 updater** 执行回滚, 而它 `source "$REPO_DIR/lib/units.sh"` 拿到的
# 已是新版(pdg_unit_singbox 早已删除)。旧代码照旧调
#     pdg_write_unit pdg_unit_singbox /etc/systemd/system/sing-box.service
# 旧实现是 `"$fn" > "$path"` —— shell **先把目标截断**才去解析命令, 于是
# sing-box.service 变成 0 字节, 界面却可能报"已回滚"。机器由此既回不到 sing-box、
# 也留不下可用 unit。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

# shellcheck source=lib/units.sh
source "$ROOT/lib/units.sh"

SENTINEL='[Unit]
Description=sing-box
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json'

# ── 1. 生成函数不存在(正是跨版本回滚的现场)→ 目标必须原样保留 ──
u="$WORK/sing-box.service"; printf '%s\n' "$SENTINEL" > "$u"
before="$(cat "$u")"
pdg_write_unit pdg_unit_singbox "$u" >/dev/null 2>&1; rc=$?
[[ "$rc" != 0 ]] && ok "生成函数不存在 → 返回非0" || bad "生成函数不存在却返回 0"
[[ -s "$u" ]] && ok "生成函数不存在 → 目标未被截断(非空)" || bad "目标被截断成 0 字节(正是跨版本回滚踩的坑)"
[[ "$(cat "$u")" == "$before" ]] && ok "生成函数不存在 → 目标内容一字未改" || bad "目标内容被改写: $(head -1 "$u")"

# ── 2. 生成函数存在但中途失败 → 同样不许留下半截 ──
_half(){ printf '[Unit]\nDescription=half'; return 1; }
printf '%s\n' "$SENTINEL" > "$u"
pdg_write_unit _half "$u" >/dev/null 2>&1; rc=$?
[[ "$rc" != 0 ]] && ok "生成函数失败 → 返回非0" || bad "生成函数失败却返回 0"
[[ "$(cat "$u")" == "$SENTINEL" ]] && ok "生成函数失败 → 目标保持原内容(不留半截)" || bad "半截内容落盘了"

# ── 3. 产出为空 → 不许写(空 unit 等于服务没了) ──
_empty(){ :; }
printf '%s\n' "$SENTINEL" > "$u"
pdg_write_unit _empty "$u" >/dev/null 2>&1; rc=$?
[[ "$rc" != 0 ]] && ok "产出为空 → 返回非0" || bad "产出为空却返回 0"
[[ "$(cat "$u")" == "$SENTINEL" ]] && ok "产出为空 → 目标保持原内容" || bad "空内容覆盖了目标"

# ── 4. 正常路径不能被这层保护搞坏 ──
rm -f "$u"
pdg_write_unit pdg_unit_mihomo "$u" >/dev/null 2>&1; rc=$?
{ [[ "$rc" == 0 ]] && grep -q 'ExecStart=/usr/local/bin/mihomo' "$u" \
  && [[ "$(stat -c %a "$u")" == 644 ]]; } \
  && ok "正常生成 → 内容正确且 644" || bad "正常路径坏了: rc=$rc mode=$(stat -c %a "$u" 2>/dev/null)"

# 覆盖既有文件也要能成功
printf 'old\n' > "$u"
pdg_write_unit pdg_unit_mihomo "$u" >/dev/null 2>&1
grep -q 'ExecStart=/usr/local/bin/mihomo' "$u" && ok "正常生成 → 可覆盖既有文件" || bad "覆盖既有文件失败"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
