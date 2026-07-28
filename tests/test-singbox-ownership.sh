#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# sing-box 文件归属保护: 更新(迁移)/卸载/--purge 都只许删**本项目装的**那份。
#
# 为什么要这条: v1.6 移除 sing-box 运行时后, 迁移与卸载都会去删 sing-box 的 unit 与
# 二进制。但机器上那份未必是我们装的 —— 用户完全可能自己跑一个 sing-box 干别的事。
# 删掉别人的东西不可逆, 也不该由本项目代为决定。
#
# 判据集中在 lib/singbox.sh(pdg / install / uninstall 共用), 满足其一才算自家的:
#   ① **可信**归属标记(文件存在且首行是约定 token; 空文件/乱写不算);
#   ② **完整匹配**历史 PDG unit 形态, **并且**现场另有本项目特征(config.json 确是我们的数据
#      模型 + 有 backend 标记)。
# 只凭一条 ExecStart 不认亲 —— 那正是手工安装 sing-box 最常见的写法, 会误删别人的东西。
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
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
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
  printf 'singbox\n' > "$SB/etc/privdns-gateway/backend"
  if [[ "$1" == ours ]]; then
    # 判据要求"形态完整匹配 + 现场另有本项目特征": config.json 必须是我们的数据模型
    printf '%s\n' '{"inbounds":[{"type":"direct","tag":"in-https"},{"type":"direct","tag":"in-http"},{"type":"mixed","tag":"tg-proxy"}]}' \
      > "$SB/etc/sing-box/config.json"
  else
    printf '%s\n' '{"inbounds":[{"type":"mixed","tag":"his-own"}]}' > "$SB/etc/sing-box/config.json"
  fi
  # 归属标记必须**可信**(首行是约定 token), 空文件不算
  [[ "${2:-}" == mark ]] && printf 'PDG-SINGBOX-OWNED v1\ncreated=2026-01-01T00:00:00Z\n' \
    > "$SB/etc/privdns-gateway/singbox.pdg-owned"
  export SB
}

run_uninstall(){   # $1=额外参数(--purge)
  mkdir -p "$WORK/lib"; cp "$ROOT/lib/singbox.sh" "$WORK/lib/"
  sed -e "s#/etc/#$SB/etc/#g" -e "s#/usr/local/bin/#$SB/usr/local/bin/#g" \
      -e "s#/opt/pdg-bot#$SB/opt/pdg-bot#g" -e "s#/opt/privdns-gateway#$SB/opt/privdns-gateway#g" \
      -e "s#/var/lib/privdns-gateway#$SB/var/lib/privdns-gateway#g" \
      -e "s#/run/systemd/#$SB/run/systemd/#g" "$ROOT/uninstall.sh" > "$WORK/u.sh"
  # 归属判据里的 ExecStart 特征是**目标机真实路径**, 不能被沙箱重写(否则判定失真)
  sed -i -e "s#$SB/usr/local/bin/sing-box run -c $SB/etc/sing-box/config#/usr/local/bin/sing-box run -c /etc/sing-box/config#" "$WORK/u.sh"
  # root 门是唯一打桩项(EUID 只读, 赋不了值), 与其它测试 stub need_root 同理; 其余逻辑原样跑
  sed -i -e 's#^\[\[ \$EUID -eq 0 \]\].*#true#' "$WORK/u.sh"
  env SB="$SB" PDG_ROOT_PREFIX="$SB" bash -c "
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

# ── 5. unit 被改过 → 形态不再完整匹配, 按"证明不了归属"保守保留 ──
# 判据已收紧为"完整形态匹配 + 本项目特征": 单条 ExecStart 是手工安装最常见的写法, 认亲会误删
# 别人的东西。代价是改过 unit 的老机器会被保守保留 —— 想让它被识别, 落一份可信归属标记即可。
mkfake ours
sed -i 's/^Description=sing-box$/Description=sing-box (我自己加了备注)/' "$SB/etc/systemd/system/sing-box.service"
run_uninstall --purge >/dev/null
[[ -e "$SB/etc/systemd/system/sing-box.service" ]] \
  && ok "unit 被改过 → 形态不匹配, 保守保留(不误删)" || bad "5: 形态不匹配却仍被删"

mkfake ours mark
sed -i 's/^Description=sing-box$/Description=sing-box (改过)/' "$SB/etc/systemd/system/sing-box.service"
run_uninstall --purge >/dev/null
[[ ! -e "$SB/etc/systemd/system/sing-box.service" ]] \
  && ok "改过的 unit + 可信归属标记 → 仍能正常清理" || bad "5b: 有标记却没清理"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
