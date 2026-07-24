#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# sing-box 文件归属保护: 更新(迁移)/卸载/--purge 都只许删**本项目装的**那份。
#
# 为什么要这条: v1.6 移除 sing-box 运行时后, 迁移与卸载都会去删 sing-box 的 unit 与
# 二进制。但机器上那份未必是我们装的 —— 用户完全可能自己跑一个 sing-box 干别的事。
# 删掉别人的东西不可逆, 也不该由本项目代为决定。
#
# 判据(与 pdg 的 _pdg_singbox_is_ours / uninstall.sh 同源):
#   ① 归属标记 /etc/privdns-gateway/singbox.pdg-owned; 或
#   ② unit 是老版 pdg_unit_singbox 生成的形态(ExecStart 指向本项目配置路径)。
# 迁移侧的归属用例在 test-migrate-drop-singbox.sh; 这里覆盖 uninstall / --purge。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

# uninstall.sh 全是绝对路径 → 重定向到沙箱根后再跑(控制流一字未改)
mkfake(){   # $1=unit 形态: ours | thirdparty ; $2=是否放归属标记
  SB="$WORK/root"; rm -rf "$SB"
  mkdir -p "$SB/etc/systemd/system" "$SB/etc/privdns-gateway" "$SB/usr/local/bin" \
           "$SB/etc/mosdns" "$SB/etc/sing-box" "$SB/etc/mihomo" "$SB/opt/pdg-bot" \
           "$SB/etc/systemd/journald.conf.d" "$SB/etc/letsencrypt/renewal-hooks/deploy" \
           "$SB/opt/privdns-gateway" "$SB/var/lib/privdns-gateway" "$SB/run/systemd/resolve"
  if [[ "$1" == ours ]]; then
    cat > "$SB/etc/systemd/system/sing-box.service" <<'U'
[Unit]
Description=sing-box
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
U
  else
    cat > "$SB/etc/systemd/system/sing-box.service" <<'U'
[Unit]
Description=my own sing-box (not PDG)
[Service]
ExecStart=/opt/mysb/sing-box run -c /opt/mysb/conf.json
U
  fi
  printf 'THIRD-PARTY-BINARY\n' > "$SB/usr/local/bin/sing-box"
  printf 'x\n' > "$SB/usr/local/bin/mihomo"
  [[ "${2:-}" == mark ]] && : > "$SB/etc/privdns-gateway/singbox.pdg-owned"
  export SB
}

run_uninstall(){   # $1=额外参数(--purge)
  sed -e "s#/etc/#$SB/etc/#g" -e "s#/usr/local/bin/#$SB/usr/local/bin/#g" \
      -e "s#/opt/pdg-bot#$SB/opt/pdg-bot#g" -e "s#/opt/privdns-gateway#$SB/opt/privdns-gateway#g" \
      -e "s#/var/lib/privdns-gateway#$SB/var/lib/privdns-gateway#g" \
      -e "s#/run/systemd/#$SB/run/systemd/#g" "$ROOT/uninstall.sh" > "$WORK/u.sh"
  # 归属判据里的 ExecStart 特征是**目标机真实路径**, 不能被沙箱重写(否则判定失真)
  sed -i -e "s#$SB/usr/local/bin/sing-box run -c $SB/etc/sing-box/config#/usr/local/bin/sing-box run -c /etc/sing-box/config#" "$WORK/u.sh"
  # root 门是唯一打桩项(EUID 只读, 赋不了值), 与其它测试 stub need_root 同理; 其余逻辑原样跑
  sed -i -e 's#^\[\[ \$EUID -eq 0 \]\].*#true#' "$WORK/u.sh"
  env SB="$SB" bash -c "
    systemctl(){ :; }; nft(){ :; }
    bash '$WORK/u.sh' ${1:-}
  " 2>&1
}

# ── 1. 第三方 sing-box: 普通卸载不得删 ──
mkfake thirdparty
out=$(run_uninstall)
[[ -e "$SB/etc/systemd/system/sing-box.service" ]] \
  && ok "卸载: 第三方 sing-box.service 保留" || bad "1: 第三方 unit 被删"
[[ -e "$SB/usr/local/bin/sing-box" ]] \
  && ok "卸载: 第三方 sing-box 二进制保留" || bad "1b: 第三方二进制被删"
grep -q '无法确认是本项目安装的' <<<"$out" \
  && ok "卸载: 明确提示已保留第三方 sing-box" || bad "1c: 无保留提示"

# ── 2. 第三方 sing-box: --purge 也不得删 ──
mkfake thirdparty
out=$(run_uninstall --purge)
[[ -e "$SB/usr/local/bin/sing-box" ]] \
  && ok "--purge: 第三方 sing-box 二进制仍保留" || bad "2: --purge 删了第三方二进制"
[[ "$(cat "$SB/usr/local/bin/sing-box")" == "THIRD-PARTY-BINARY" ]] \
  && ok "--purge: 第三方二进制内容未被动过" || bad "2b: 内容被改"
grep -q '保留' <<<"$out" && ok "--purge: 给出保留提示" || bad "2c: 无提示"
# 项目自己的东西该删还得删(不能因保护把卸载搞成空操作)
[[ ! -e "$SB/usr/local/bin/mihomo" ]] && ok "--purge: 项目自己的 mihomo 仍被删(保护没误伤卸载)" || bad "2d: mihomo 没删"
[[ ! -d "$SB/etc/mosdns" ]] && ok "--purge: 项目配置目录仍被删" || bad "2e: /etc/mosdns 没删"

# ── 3. 本项目装的 sing-box: 该删就删 ──
mkfake ours
run_uninstall --purge >/dev/null
[[ ! -e "$SB/etc/systemd/system/sing-box.service" ]] \
  && ok "--purge: 本项目装的 sing-box.service 已删" || bad "3: 自家 unit 没删"
[[ ! -e "$SB/usr/local/bin/sing-box" ]] \
  && ok "--purge: 本项目装的 sing-box 二进制已删" || bad "3b: 自家二进制没删"

# ── 4. 归属标记优先: 即便 unit 形态不匹配也认得出是自家的 ──
mkfake thirdparty mark
run_uninstall --purge >/dev/null
[[ ! -e "$SB/usr/local/bin/sing-box" ]] \
  && ok "--purge: 归属标记存在 → 认定自家并删除" || bad "4: 归属标记未生效"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
