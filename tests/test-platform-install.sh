#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 平台隔离: 安装/更新/迁移矩阵回归(pdg.sh 迁移函数, 打桩 + 沙箱路径, 不碰真 /)。
#   A. migrate_platform_marker: platform 文件 / profile.env / pdg-mitm 证据 / WLOC 证据 / 完全缺失。
#   B. GMS 防火墙端口迁移: Android 补 5228-5230, iOS 跳过(sing-box 侧已随内核退役)。
#   C. migrate_ios_gms_cleanup: 删 in-gms-* 入站 + nft 移除 5228-5230(iOS)。
#   D. migrate_android_cleanup: 删 iOS 专属 unit/文件, 保留 CA/地点数据为休眠。
#   E. _pdg_svcs: Android 无 pdg-probe81, iOS 有。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }
xt(){ sed -n "/^$1(){/,/^}/p" "$ROOT/deploy/bot/pdg.sh"; }   # 抽取一个函数体
skip(){ echo "[SKIP] $1"; }                                  # 不计入 pass: 没断言就别冒充断言
# 抽真身并确认它真的到位了。函数被改名/删除时 xt 只输出空串, eval "" 又是成功的 —— 后面的
# `f x && bad || ok` 就会因为 127(command not found)稳稳落到 ok 分支, 整段变成假绿
# (migrate_singbox_gms 随 sing-box 退役后, 本文件就这么绿了一整轮)。
use_fn(){
  local f body
  for f in "$@"; do
    body="$(xt "$f")"
    [[ -n "$body" ]] || { bad "抽取失败: pdg.sh 里没有 $f()"; return 1; }
    eval "$body" || { bad "eval 函数体失败: $f"; return 1; }
    declare -F "$f" >/dev/null || { bad "eval 后函数仍不存在: $f"; return 1; }
  done
}
# 关键调用: 退出码非 0(127=命令不存在也在内)一律记 FAIL, 不指望后面的 grep 替它兜底
run_ok(){
  local what="$1"; shift; local out rc
  out="$("$@" 2>&1)"; rc=$?
  (( rc == 0 )) && return 0
  bad "$what: 退出码 $rc | $(tr '\n' ' ' <<<"$out" | head -c 200)"
  return 1
}

# ── A. migrate_platform_marker(路径 env 注入)──────────────────────────────────
use_fn migrate_platform_marker
c_g(){ :; }; c_y(){ :; }
mk_marker(){ PDG_PLATFORM_FILE="$WORK/platform" PROFILE_ENV="$WORK/profile.env" \
             PDG_MITM_JSON="$WORK/mitm.json" PDG_MITM_UNIT="$WORK/pdg-mitm.service" \
             migrate_platform_marker || bad "migrate_platform_marker 退出码 $?"; }
reset_ev(){ rm -f "$WORK/platform" "$WORK/profile.env" "$WORK/mitm.json" "$WORK/pdg-mitm.service" "$WORK/platform.guessed"; }

reset_ev; printf 'ios\n' > "$WORK/platform"; mk_marker
[[ "$(cat "$WORK/platform")" == ios ]] && ok "标记已合法(ios) → 幂等不改" || bad "误改了合法标记"
reset_ev; printf 'PDG_PLATFORM=ios\n' > "$WORK/profile.env"; mk_marker
[[ "$(cat "$WORK/platform")" == ios ]] && ok "缺标记 → 读 profile.env PDG_PLATFORM=ios" || bad "profile.env 证据未生效"
reset_ev; printf 'PDG_PLATFORM=android\n' > "$WORK/profile.env"; mk_marker
[[ "$(cat "$WORK/platform")" == android ]] && ok "缺标记 → 读 profile.env PDG_PLATFORM=android" || bad "android 证据未生效"
reset_ev; : > "$WORK/pdg-mitm.service"; mk_marker
[[ "$(cat "$WORK/platform")" == ios ]] && ok "缺标记 → pdg-mitm unit 证据 → ios" || bad "pdg-mitm 证据未生效"
reset_ev; printf '{"wloc":{"enabled":false}}\n' > "$WORK/mitm.json"; mk_marker
[[ "$(cat "$WORK/platform")" == ios ]] && ok "缺标记 → WLOC 配置证据 → ios" || bad "WLOC 证据未生效"
reset_ev; mk_marker
[[ "$(cat "$WORK/platform")" == android ]] && ok "无任何证据 → 安全回退 android" || bad "回退未生效"

# ── E. _pdg_svcs(平台服务集)──────────────────────────────────────────────────
use_fn _pdg_svcs; _pdg_core_svc(){ echo sing-box; }
_pdg_platform(){ echo android; }
[[ "$(_pdg_svcs)" == "mosdns sing-box pdg-bot" ]] && ok "Android 服务集不含 pdg-probe81" || bad "Android 服务集错: $(_pdg_svcs)"
_pdg_platform(){ echo ios; }
[[ "$(_pdg_svcs)" == *pdg-probe81* ]] && ok "iOS 服务集含 pdg-probe81" || bad "iOS 服务集缺 pdg-probe81"

# ── A2. 推测出来的 android 必须打 .guessed, 且不做破坏性 iOS 清理(v1.4.x 老装保护) ──
# v1.4.x 无平台概念, 且把 probe81/描述文件装给**所有**机器 —— 它们的存在证明不了平台。
# 之前直接回退 android 并照常清理, 会把真 iPhone 部署的 iOS 组件删光, 而且之后 doctor 全绿。
reset_ev; mk_marker
{ [[ "$(cat "$WORK/platform")" == android ]] && [[ -e "$WORK/platform.guessed" ]]; } \
  && ok "无任何证据 → 回退 android 并打 .guessed(推测)" || bad "A2: 未标记为推测"
reset_ev; printf 'PDG_PLATFORM=android\n' > "$WORK/profile.env"; mk_marker
{ [[ "$(cat "$WORK/platform")" == android ]] && [[ ! -e "$WORK/platform.guessed" ]]; } \
  && ok "有确凿证据(profile.env) → 不打 .guessed" || bad "A2b: 确凿证据也被当成推测"

# 推测状态下 migrate_android_cleanup 必须跳过破坏性清理
use_fn migrate_android_cleanup
c_y(){ echo "$*"; }        # 本段要断言提示文案(文件顶部把 c_y 打桩成静默了)
reset_ev; mk_marker                     # → android + .guessed
mkdir -p "$WORK/optbot"; : > "$WORK/optbot/probe81.py"
_pdg_platform(){ echo android; }
out=$(PDG_PLATFORM_FILE="$WORK/platform" migrate_android_cleanup 2>&1)
{ grep -q '跳过 iOS 组件清理' <<<"$out" && [[ -e "$WORK/optbot/probe81.py" ]]; } \
  && ok "推测的 android → 跳过 iOS 组件清理(不冒删 iPhone 部署的风险)" || bad "A2c: out=$out"
rm -f "$WORK/platform.guessed"
out=$(PDG_PLATFORM_FILE="$WORK/platform" migrate_android_cleanup 2>&1)
grep -q '跳过 iOS 组件清理' <<<"$out" && bad "A2d: 已确认仍跳过清理" || ok "确认后的 android → 正常执行清理"
c_y(){ :; }                # 恢复静默, 不干扰后续用例

# ── A3. migrate_backend_marker: 老装(v1.4.x)从无 backend 标记, 必须据现场证据落地 ──
# 隐患: 一直靠 _pdg_core 的默认值 singbox 兜底; 默认值将来一改就会静默换核, 而机器上
# 可能根本没装那个内核。抽真身 + 绝对路径重定向到沙箱(不给生产代码加接缝)。
BM="$WORK/bm"; mkdir -p "$BM/etc/privdns-gateway" "$BM/etc/systemd/system" "$BM/etc/mihomo"
xt migrate_backend_marker | sed -e "s#/etc/#$BM/etc/#g" > "$WORK/bmfn.sh"
bm_run(){ # $1=额外桩
  rm -f "$BM/etc/privdns-gateway/backend"
  bash -c "set -uo pipefail
c_g(){ echo \"\$*\"; }; c_y(){ :; }
install(){ command install \"\$@\"; }
$1
source '$WORK/bmfn.sh'
migrate_backend_marker >/dev/null 2>&1
cat '$BM/etc/privdns-gateway/backend' 2>/dev/null || echo '(无)'"
}
rm -f "$BM/etc/systemd/system/"*.service "$BM/etc/mihomo/config.yaml"
[[ "$(bm_run 'systemctl(){ echo inactive; return 1; }')" == singbox ]] \
  && ok "backend: 无任何证据 → 兜底 singbox(与历史默认一致)" || bad "A3a"

: > "$BM/etc/systemd/system/mihomo.service"
[[ "$(bm_run 'systemctl(){ [[ "$1" == is-active ]] && echo active; return 0; }')" == mihomo ]] \
  && ok "backend: mihomo unit 存在且 active → mihomo" || bad "A3b"

rm -f "$BM/etc/systemd/system/mihomo.service"; : > "$BM/etc/systemd/system/sing-box.service"
[[ "$(bm_run 'systemctl(){ [[ "$1" == is-active ]] && echo active; return 0; }')" == singbox ]] \
  && ok "backend: sing-box unit 存在且 active → singbox" || bad "A3c"

# unit 文件不存在时, is-active 谎报 active 也不能被采信(正是加 unit 存在性前置的原因)
rm -f "$BM/etc/systemd/system/"*.service
[[ "$(bm_run 'systemctl(){ [[ "$1" == is-active ]] && echo active; return 0; }')" == singbox ]] \
  && ok "backend: unit 不存在时不轻信 is-active(不误判成 mihomo)" || bad "A3d"

# 已有合法标记 → 幂等不改
printf 'mihomo\n' > "$BM/etc/privdns-gateway/backend"
out=$(bash -c "c_g(){ :; }; c_y(){ :; }; install(){ :; }; systemctl(){ echo active; }
source '$WORK/bmfn.sh'; migrate_backend_marker; cat '$BM/etc/privdns-gateway/backend'" 2>/dev/null)
[[ "$out" == mihomo ]] && ok "backend: 已有合法标记 → 幂等不改" || bad "A3e: $out"

# ── B. GMS 防火墙端口迁移: 仅 Android 补 5228-5230, iOS 跳过 ──────────────
# sing-box 侧的 migrate_singbox_gms 已随 sing-box 运行时一并退役, 原用例调的是一个不存在的
# 函数(见文件头 use_fn 注释)。换成**当前仍在跑**的防火墙侧, 并钉住"它确实没了": 哪天再冒
# 出来, 得连同它的平台跳过用例一起补回来, 而不是又静静地假绿。
if grep -q '^migrate_singbox_gms()' "$ROOT/deploy/bot/pdg.sh"; then
  bad "migrate_singbox_gms 又回来了: 需要补回它的 iOS 跳过用例"
else
  ok "migrate_singbox_gms 已随 sing-box 退役(不再有 model 入站迁移)"
fi
use_fn migrate_fw_gms
systemctl(){ [[ "$1" == is-active ]] && echo active; return 0; }
nft(){ return 0; }              # -c 校验与加载都当成功: 本段只验改写判据
nf_orig='table inet pdg {\n  ip saddr 10.0.0.0/16 tcp dport { 53, 80, 81, 443, 853, 8445 } accept\n}\n'
# iOS: 原装形态也不能补 —— GMS/FCM 是 Android 的推送通道
_pdg_platform(){ echo ios; }
printf "$nf_orig" > "$WORK/nf"
run_ok "migrate_fw_gms(iOS)" migrate_fw_gms "$WORK/nf"
grep -q '5228' "$WORK/nf" && bad "iOS 不应补 GMS 防火墙端口" || ok "migrate_fw_gms: iOS 跳过(不补 5228-5230)"
# Android: 原装形态要补上
_pdg_platform(){ echo android; }
printf "$nf_orig" > "$WORK/nf"
run_ok "migrate_fw_gms(Android)" migrate_fw_gms "$WORK/nf"
grep -qF 'tcp dport { 53, 80, 81, 443, 853, 5228-5230, 8445 } accept' "$WORK/nf" \
  && ok "migrate_fw_gms: Android 原装端口集补上 5228-5230" || bad "Android 未补 GMS 端口: $(cat "$WORK/nf")"
snapb="$(cat "$WORK/nf")"
run_ok "migrate_fw_gms(幂等)" migrate_fw_gms "$WORK/nf"
[[ "$(cat "$WORK/nf")" == "$snapb" ]] && ok "migrate_fw_gms: 已有 5228 → 幂等不再改" || bad "二跑又改了防火墙配置"
# 自定义端口集不认: 宁可提示手动加, 也不猜着改用户的规则
printf 'table inet pdg {\n  ip saddr 10.0.0.0/16 tcp dport { 53, 443, 9443 } accept\n}\n' > "$WORK/nfcust"
snapb="$(cat "$WORK/nfcust")"
run_ok "migrate_fw_gms(自定义)" migrate_fw_gms "$WORK/nfcust"
[[ "$(cat "$WORK/nfcust")" == "$snapb" ]] && ok "migrate_fw_gms: 非原装端口集不自动改写" || bad "改写了自定义端口集"
rm -f "$WORK"/nf.pregms.* "$WORK"/nfcust.pregms.*

# ── C. migrate_ios_gms_cleanup: 删 in-gms-* + nft 移除 5228-5230 ────────────────
use_fn migrate_ios_gms_cleanup _pdg_nft_strip_gms; _pdg_core_svc(){ echo sing-box; }
cat > "$WORK/sbg.json" <<'JSON'
{"inbounds":[{"type":"direct","tag":"in-https","listen_port":443},
             {"type":"direct","tag":"in-gms-5228","listen_port":5228},
             {"type":"direct","tag":"in-gms-5229","listen_port":5229},
             {"type":"direct","tag":"in-gms-5230","listen_port":5230}],"outbounds":[],"route":{}}
JSON
printf 'table inet pdg {\n  chain input { ip saddr 10.0.0.0/16 tcp dport { 53, 80, 81, 443, 853, 5228-5230, 8445 } accept }\n}\n' > "$WORK/nfg"
_pdg_platform(){ echo ios; }
run_ok "migrate_ios_gms_cleanup(iOS)" migrate_ios_gms_cleanup "$WORK/sbg.json" "$WORK/nfg"
{ ! grep -q 'in-gms-5228' "$WORK/sbg.json" && ! grep -q 'in-gms-5230' "$WORK/sbg.json"; } \
  && ok "iOS 清理: sing-box 删掉 in-gms-5228/5229/5230 入站" || bad "in-gms-* 未删净"
grep -q 'in-https' "$WORK/sbg.json" && ok "iOS 清理: 非 GMS 入站(in-https)保留" || bad "误删了非 GMS 入站"
grep -q '5228' "$WORK/nfg" && bad "nft 仍含 5228" || ok "iOS 清理: nft 端口集移除 5228-5230"
# iOS 清理幂等: 再跑不变
snap="$(cat "$WORK/sbg.json")"
run_ok "migrate_ios_gms_cleanup(幂等)" migrate_ios_gms_cleanup "$WORK/sbg.json" "$WORK/nfg"
[[ "$(cat "$WORK/sbg.json")" == "$snap" ]] && ok "iOS 清理幂等(二跑不变)" || bad "二跑改动了配置"
# Android 上该清理跳过
_pdg_platform(){ echo android; }
cat > "$WORK/sba.json" <<'JSON'
{"inbounds":[{"type":"direct","tag":"in-gms-5228","listen_port":5228}],"outbounds":[],"route":{}}
JSON
run_ok "migrate_ios_gms_cleanup(Android)" migrate_ios_gms_cleanup "$WORK/sba.json" "$WORK/nfg"
grep -q 'in-gms-5228' "$WORK/sba.json" && ok "Android: iOS GMS 清理不执行(保留 GMS)" || bad "Android 误删了 GMS"

# ── C3. mihomo REDIRECT 形态: 只从端口集去 5228-5230, 必须保留整条 { 80, 443 } redirect ──
# 回归: 旧实现 sed 按行删含 5228 的 redirect → 连 80/443 一起删掉 → 网关 80/443 不再 REDIRECT 到 mihomo(断网)。
_pdg_platform(){ echo ios; }
printf 'table inet pdg {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tip saddr 172.22.0.0/16 tcp dport { 80, 443, 5228-5230 } redirect to :7893\n\t}\n}\n' > "$WORK/nfmh"
run_ok "migrate_ios_gms_cleanup(mihomo)" migrate_ios_gms_cleanup "$WORK/none-sb.json" "$WORK/nfmh"   # sb 不存在 → 只走 nft 分支
grep -qE 'tcp dport [{][^}]*5228' "$WORK/nfmh" && bad "mihomo: 端口集仍含 5228-5230" || ok "mihomo: 端口集已精确去掉 5228-5230"
grep -qF 'tcp dport { 80, 443 } redirect to :7893' "$WORK/nfmh" && ok "mihomo: { 80, 443 } redirect 整条保留(不再误删)" || bad "mihomo: 80/443 redirect 被误删!"
snap="$(cat "$WORK/nfmh")"
run_ok "migrate_ios_gms_cleanup(mihomo 幂等)" migrate_ios_gms_cleanup "$WORK/none-sb.json" "$WORK/nfmh"
[[ "$(cat "$WORK/nfmh")" == "$snap" ]] && ok "mihomo REDIRECT 清理幂等(二跑不变)" || bad "二跑改动了 nft"
# nft 语法校验: 需要真 nft 二进制(type -P 只找可执行文件, 绕开本测试里的 nft() 桩), 且本环境
# 确实能跑 nft -c —— nft 即便只做 -c 也要开 netlink, 非 root(如 CI runner)会连合法规则集一起拒。
# 故先用一份**手写的合法 nat/redirect 规则集**探能力: 探测过 = 本环境能校验这类规则, 此时迁移
# 产物再不过就是真的错(照报 FAIL); 探测不过 = 环境不具备校验能力, 跳过而非谎报通过。
_nftbin="$(type -P nft 2>/dev/null || true)"
printf 'table inet nftprobe {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tip saddr 172.22.0.0/16 tcp dport { 80, 443 } redirect to :7893\n\t}\n}\n' > "$WORK/nftprobe"
if [[ -n "$_nftbin" ]] && "$_nftbin" -c -f "$WORK/nftprobe" >/dev/null 2>&1; then
  if "$_nftbin" -c -f "$WORK/nfmh" >/dev/null 2>&1; then ok "迁移后 nft -c 校验通过"
  else bad "迁移后 nft -c 校验不过: $("$_nftbin" -c -f "$WORK/nfmh" 2>&1 | head -2 | tr '\n' ' ')"; fi
else
  skip "迁移后 nft -c 校验: 本环境 nft 不可用或无 netlink 权限(CI 的容器 E2E 里有真 nft)"
fi
# 自定义/非原装 5228 形态(逐端口而非区间)无法安全识别 → 还原不破坏
printf 'table inet pdg {\n\tchain prerouting { ip saddr X tcp dport { 80, 443, 5228, 5229, 5230 } redirect to :7893 }\n}\n' > "$WORK/nfcustom"
snapc="$(cat "$WORK/nfcustom")"
run_ok "migrate_ios_gms_cleanup(自定义)" migrate_ios_gms_cleanup "$WORK/none-sb.json" "$WORK/nfcustom"
[[ "$(cat "$WORK/nfcustom")" == "$snapc" ]] && ok "自定义 5228 形态无法安全识别 → 还原不破坏配置" || bad "破坏了自定义配置"

# ── C2. _pdg_nft_strip_gms: iOS 渲染后剥掉 GMS(装机/切核共用)──────────────────
printf 'table inet pdg {\n  ip saddr 10.0.0.0/16 tcp dport { 53, 80, 81, 443, 853, 5228-5230, 8445 } accept\n  ip saddr 10.0.0.0/16 tcp dport { 80, 443, 5228-5230 } redirect to :7893\n}\n' > "$WORK/nfr"
_pdg_platform(){ echo ios; }
run_ok "_pdg_nft_strip_gms(iOS)" _pdg_nft_strip_gms "$WORK/nfr"
grep -q '5228' "$WORK/nfr" && bad "iOS strip 未去净 5228-5230" || ok "_pdg_nft_strip_gms(iOS): 端口集 + REDIRECT 均去掉 5228-5230"
grep -q '8445' "$WORK/nfr" && grep -q 'redirect to :7893' "$WORK/nfr" && ok "strip 只去 GMS, 其余端口/REDIRECT 保留" || bad "strip 误伤其它端口"
printf 'x tcp dport { 53, 80, 81, 443, 853, 5228-5230, 8445 } accept\n' > "$WORK/nfa"
_pdg_platform(){ echo android; }
run_ok "_pdg_nft_strip_gms(Android)" _pdg_nft_strip_gms "$WORK/nfa"
grep -q '5228-5230' "$WORK/nfa" && ok "Android: _pdg_nft_strip_gms 空操作(保留 GMS)" || bad "Android 误删了 GMS"

# ── D. migrate_android_cleanup: 删 iOS 残留 unit/文件, 保留 CA/地点数据 ──────────
# 该函数用绝对路径(/etc/systemd/system, /opt/pdg-bot) → 沙箱难注入; 用静态断言核对关键行为。
u="$ROOT/deploy/bot/pdg.sh"
grep -q 'migrate_android_cleanup' "$u" && grep -q 'disable --now "\$u"' "$u" && ok "存在 Android 残留清理(停用+删 pdg-probe81/pdg-mitm unit)" || bad "缺 Android 清理逻辑"
grep -q 'CA/地点数据保留为休眠' "$u" && ok "Android 清理保留 CA/地点数据(不永久删)" || bad "未保留用户数据"
grep -q 'migrate_deploy_botfiles' "$u" && grep -q 'mitm_ca.py|mitm_server.py|mitm_wloc.py) \[\[ "\$plat" == ios \]\] || continue' "$u" \
  && ok "migrate_deploy_botfiles: Android 不部署 iOS MITM 模块" || bad "botfiles 未按平台部署"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
