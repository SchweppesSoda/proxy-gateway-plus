#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# v1.6.0 回归: 旧 sing-box 机器迁到 mihomo(migrate_drop_singbox / _activate_mihomo_core)。
#
# 两件事必须成立:
#   ① 失败时说清**为什么**(承自 issue #1: 旧 switch-core 把三种完全不同的失败挤成一句
#      "渲染/校验失败", python 的 stderr 还被 2>/dev/null 丢掉 —— 用户拿不到任何线索);
#   ② 失败必须**返回非 0 且回滚 backend 标记**, 好让 run_all_migrations 把非 0 传给
#      cmd_update → 回滚到更新前快照(绝不把机器留在半迁移态, 也绝不静默丢出口)。
#   成功路径则要真把 sing-box 运行时清干净(unit + 二进制)并落定 backend=mihomo。
#
# 沙箱化: 抽出真实函数, 只把绝对路径字面量重定向到临时根, 其余打桩。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

sed -n '/^_pdg_singbox_is_ours(){/,/^}/p'   "$ROOT/deploy/bot/pdg.sh"  > "$WORK/fn.sh"
sed -n '/^_pdg_drop_singbox_files(){/,/^}/p' "$ROOT/deploy/bot/pdg.sh" >> "$WORK/fn.sh"
sed -n '/^_activate_mihomo_core(){/,/^}/p'   "$ROOT/deploy/bot/pdg.sh" >> "$WORK/fn.sh"
sed -n '/^migrate_drop_singbox(){/,/^}/p'    "$ROOT/deploy/bot/pdg.sh" >> "$WORK/fn.sh"
grep -q '^_activate_mihomo_core(){' "$WORK/fn.sh" || { echo "抽取 _activate_mihomo_core 失败"; exit 1; }
grep -q '^migrate_drop_singbox(){'  "$WORK/fn.sh" || { echo "抽取 migrate_drop_singbox 失败"; exit 1; }
grep -q '^_pdg_singbox_is_ours(){' "$WORK/fn.sh" || { echo "抽取归属助手失败"; exit 1; }
# 绝对路径 → 沙箱(控制流与变量引用一字未改)
sed -i -e 's#/etc/#$SB/etc/#g' -e 's#/opt/pdg-bot#$SB/opt/pdg-bot#g' \
       -e 's#/usr/local/bin/#$SB/usr/local/bin/#g' "$WORK/fn.sh"
# 归属判据里的 ExecStart 特征行是**目标机上的真实路径**, 不能被上面的沙箱重写改掉
sed -i -e 's#\$SB/usr/local/bin/sing-box run -c \$SB/etc/sing-box/config#/usr/local/bin/sing-box run -c /etc/sing-box/config#' "$WORK/fn.sh"

mk(){   # $1=当前 backend 标记; 造出"仍是 sing-box 的老机器"现场
  SB="$WORK/root"; rm -rf "$SB"
  mkdir -p "$SB/etc/privdns-gateway" "$SB/etc/mihomo" "$SB/etc/sing-box" \
           "$SB/etc/systemd/system" "$SB/opt/pdg-bot" "$SB/usr/local/bin"
  printf '%s\n' "$1" > "$SB/etc/privdns-gateway/backend"
  printf '{}\n' > "$SB/etc/privdns-gateway/mitm.json"
  printf 'x\n'  > "$SB/etc/nftables.conf"
  printf 'y\n'  > "$SB/etc/mihomo/config.yaml"
  printf '{}\n' > "$SB/etc/sing-box/config.json"
  printf '#!/bin/sh\nexit 0\n' > "$SB/usr/local/bin/sing-box"; chmod 755 "$SB/usr/local/bin/sing-box"
  # 用**老版装机真正生成的** unit 形态(lib/units.sh 历史模板 pdg_unit_singbox), 否则归属
  # 判定认不出它是本项目的东西 —— 那正是第三方 sing-box 该走的分支, 不能拿它冒充自家的。
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
  export SB
}

harness(){ cat <<'EOF'
need_root(){ :; }; _lock(){ :; }
c_g(){ echo "$*"; }; c_y(){ echo "$*"; }
cmd_snapshot(){ :; }
dpkg(){ echo amd64; }
pdg_write_unit(){ :; }
systemctl(){ :; }
journalctl(){ echo "(stub journal)"; }
_switchcore_nft(){ return "${NFT_RC:-0}"; }
_core_kernel_activate(){ return "${ACTIVATE_RC:-0}"; }
_core_kernel_restore(){ :; }
_pdg_platform(){ echo android; }
pdg_verify_sha256(){ return 0; }
cp(){ command cp "$@" 2>/dev/null || true; }
mihomo(){
  case "${1:-}" in
    -v) echo "Mihomo Meta $MIHOMO_VER";;             # 已是钉死版本, 跳过下载
    -t) [[ -n "${MIHOMO_T_FAIL:-}" ]] && { echo "$MIHOMO_T_ERR" >&2; return 1; }; return 0;;
  esac
  return 0
}
# 渲染预检: 由 RENDER_MODE 决定 python 的行为
python3(){
  case "${RENDER_MODE:-ok}" in
    ok)      return 0;;
    raise)   echo "渲染 mihomo 配置失败: ValueError: 出口 xyz 缺 server 字段" >&2; return 1;;
    unknown) echo "这些出口 mihomo 无法转换(迁移会凭空丢失): hy1-jp, ssr-tw" >&2; return 1;;
  esac
}
EOF
}

run(){  # $1=env $2=要调的函数
  # shellcheck disable=SC2086
  env SB="$SB" $1 bash -c "set -uo pipefail
REPO_DIR='$ROOT'
$(harness)
source '$ROOT/lib/versions.sh' 2>/dev/null
source '$WORK/fn.sh'
$2; echo \"RC=\$?\"" 2>&1
}

# ── 1. 有出口无法转换 → 列出是哪几个出口 + 非0 + 回滚标记(绝不静默丢出口) ──
mk singbox
out=$(run "RENDER_MODE=unknown" migrate_drop_singbox)
{ grep -q 'hy1-jp' <<<"$out" && grep -q 'ssr-tw' <<<"$out" && grep -q 'RC=1' <<<"$out"; } \
  && ok "转换失败: 逐个列出无法转换的出口名 + 返回非0(触发 update 回滚)" || bad "1: out=$out"
[[ "$(cat "$SB/etc/privdns-gateway/backend")" == singbox ]] \
  && ok "转换失败: backend 标记已回滚(不留半迁移态)" || bad "1b: backend=$(cat "$SB/etc/privdns-gateway/backend")"
[[ -e "$SB/usr/local/bin/sing-box" && -e "$SB/etc/systemd/system/sing-box.service" ]] \
  && ok "转换失败: sing-box 运行时原样保留(用户仍可用旧版)" || bad "1c: sing-box 被误删"

# ── 2. 渲染抛异常 → 带出异常类型与信息 ──
mk singbox
out=$(run "RENDER_MODE=raise" migrate_drop_singbox)
{ grep -q 'ValueError' <<<"$out" && grep -q '缺 server 字段' <<<"$out" && grep -q 'RC=1' <<<"$out"; } \
  && ok "渲染异常: 带出异常类型与原始信息 + 非0" || bad "2: out=$out"

# ── 3. mihomo -t 不过 → 带出 mihomo 自己的报错 ──
mk singbox
out=$(run "RENDER_MODE=ok MIHOMO_T_FAIL=1 MIHOMO_T_ERR=rule_9_is_invalid_xyz" migrate_drop_singbox)
{ grep -q 'rule_9_is_invalid_xyz' <<<"$out" && grep -q 'mihomo 配置校验失败' <<<"$out" && grep -q 'RC=1' <<<"$out"; } \
  && ok "mihomo -t 失败: 带出内核真实报错 + 非0" || bad "3: out=$out"

# ── 4. nft 应用失败 → 回滚标记 + 非0 ──
mk singbox
out=$(run "RENDER_MODE=ok NFT_RC=1" migrate_drop_singbox)
{ grep -q 'nft 应用失败' <<<"$out" && grep -q 'RC=1' <<<"$out"; } \
  && ok "nft 失败: 报明原因 + 非0" || bad "4: out=$out"
[[ "$(cat "$SB/etc/privdns-gateway/backend")" == singbox ]] \
  && ok "nft 失败: backend 标记已回滚" || bad "4b"

# ── 5. 内核起不来 → 回滚并附上日志线索 ──
mk singbox
out=$(run "RENDER_MODE=ok ACTIVATE_RC=1" migrate_drop_singbox)
{ grep -q '已回滚' <<<"$out" && grep -q '最近日志' <<<"$out" && grep -q 'RC=1' <<<"$out"; } \
  && ok "内核起不来: 回滚 + 附内核日志线索 + 非0" || bad "5: out=$out"
[[ -e "$SB/usr/local/bin/sing-box" ]] \
  && ok "内核起不来: sing-box 二进制未删(还能退回去)" || bad "5b: sing-box 被误删"

# ── 6. 一切正常 → 迁移成功, sing-box 运行时清干净, backend 落定 mihomo ──
mk singbox
out=$(run "RENDER_MODE=ok" migrate_drop_singbox)
{ grep -q 'RC=0' <<<"$out" && grep -q 'sing-box 运行时已移除' <<<"$out"; } \
  && ok "正常路径: 迁移成功并明确告知已移除 sing-box" || bad "6: out=$out"
[[ "$(cat "$SB/etc/privdns-gateway/backend")" == mihomo ]] \
  && ok "正常路径: backend 落定 mihomo" || bad "6b: backend=$(cat "$SB/etc/privdns-gateway/backend")"
[[ ! -e "$SB/usr/local/bin/sing-box" ]] \
  && ok "正常路径: sing-box 二进制已删" || bad "6c: sing-box 二进制仍在"
[[ ! -e "$SB/etc/systemd/system/sing-box.service" ]] \
  && ok "正常路径: sing-box.service 已删" || bad "6d: unit 仍在"

# ── 7. 幂等: 已是纯 mihomo 的机器再跑一次 → 直接短路返回 0, 不重复迁移 ──
mk mihomo
rm -f "$SB/usr/local/bin/sing-box" "$SB/etc/systemd/system/sing-box.service"
out=$(run "RENDER_MODE=raise" migrate_drop_singbox)   # 渲染故意会炸: 短路了就压根不会调到
{ grep -q 'RC=0' <<<"$out" && ! grep -q 'ValueError' <<<"$out"; } \
  && ok "幂等: 已是纯 mihomo → 短路返回0(不重复迁移)" || bad "7: out=$out"

# ── 8. 归属保护: 机器上是**第三方**的 sing-box(不是本项目装的)→ 一律不删 ──
# 用户完全可能自己在跑一个 sing-box 干别的; 删掉别人的东西不可逆。
tp_unit(){ cat > "$SB/etc/systemd/system/sing-box.service" <<'U'
[Unit]
Description=sing-box service (third party, hand rolled)
[Service]
ExecStart=/opt/mysingbox/sing-box run -c /opt/mysingbox/my.json
U
}
mk singbox; tp_unit
out=$(run "RENDER_MODE=ok" migrate_drop_singbox)
{ [[ -e "$SB/etc/systemd/system/sing-box.service" ]] && [[ -e "$SB/usr/local/bin/sing-box" ]]; } \
  && ok "第三方 sing-box: 迁移完成后文件原样保留(不删别人的东西)" || bad "8: 第三方 sing-box 被删了"
grep -q '无法确认是本项目安装的' <<<"$out" \
  && ok "第三方 sing-box: 明确告知已保留 + 给出手工清理指引" || bad "8b: 没有保留提示: $out"

# backend 已是 mihomo 且只剩第三方 sing-box → 不该每次更新都去动它(也不重复迁移)
mk mihomo; tp_unit
out=$(run "RENDER_MODE=raise" migrate_drop_singbox)   # 渲染会炸: 真去迁移就会暴露
{ grep -q 'RC=0' <<<"$out" && ! grep -q 'ValueError' <<<"$out" \
  && [[ -e "$SB/etc/systemd/system/sing-box.service" ]]; } \
  && ok "已是 mihomo + 第三方 sing-box: 不重复迁移也不删它" || bad "8c: out=$out"

# 带归属标记的(本项目装的)→ 即便 unit 形态不匹配也认得出来, 该删就删
mk singbox; tp_unit; : > "$SB/etc/privdns-gateway/singbox.pdg-owned"
out=$(run "RENDER_MODE=ok" migrate_drop_singbox)
[[ ! -e "$SB/etc/systemd/system/sing-box.service" ]] \
  && ok "带归属标记: 认定为本项目安装 → 正常清理" || bad "8d: 归属标记未生效"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
