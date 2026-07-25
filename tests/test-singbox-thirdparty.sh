#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 第三方 sing-box 必须毫发无损(P0)。
#
# 之前的归属判据只看一条 ExecStart:
#     ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
# 这是**手工安装最常见的写法** —— 拿它当"本项目所有"的证明, 等于把别人按常规装的 sing-box
# 认成自家的, 然后在迁移/卸载时删掉它的 unit、二进制, 甚至整个 /etc/sing-box。不可逆。
#
# 现在要求: 只有 ① 可信归属标记, 或 ② **完整匹配**历史 PDG unit 形态 **且** 现场另有本项目
# 特征(config.json 确实是我们的数据模型 + 存在 backend 标记), 才算自家的。证明不了 → 全保留。
#
# 本用例造的第三方现场刻意"长得最像": ExecStart 与 PDG 历史形态**逐字一致**, 但 config.json
# 是他自己的(带唯一 sentinel)。断言: 迁移 / 卸载 / --purge 之后, unit、二进制、配置目录与
# sentinel 全部逐字节未变; 而确属旧版 PDG 的 sing-box 仍能被正常清理。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

SENTINEL='THIRD-PARTY-SENTINEL-9f2c1a'

# 历史 PDG unit 形态(v1.4.2 起逐字未变) —— 第三方也可能恰好这么写, 故不能只凭它认亲
PDG_UNIT='[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target'

mk(){   # $1 = thirdparty | pdg
  SB="$WORK/root"; rm -rf "$SB"
  mkdir -p "$SB/etc/systemd/system" "$SB/etc/privdns-gateway" "$SB/usr/local/bin" \
           "$SB/etc/sing-box" "$SB/etc/mosdns" "$SB/etc/mihomo" "$SB/opt/pdg-bot" \
           "$SB/etc/systemd/journald.conf.d" "$SB/opt/privdns-gateway" "$SB/var/lib/privdns-gateway"
  printf '%s\n' "$PDG_UNIT" > "$SB/etc/systemd/system/sing-box.service"   # 两种现场都用同一形态
  printf 'BINARY-CONTENT\n' > "$SB/usr/local/bin/sing-box"; chmod 755 "$SB/usr/local/bin/sing-box"
  if [[ "$1" == thirdparty ]]; then
    # 他自己的配置(带唯一 sentinel), 不是本项目的数据模型
    cat > "$SB/etc/sing-box/config.json" <<J
{ "log": {"level": "info"}, "note": "$SENTINEL",
  "inbounds": [{"type": "mixed", "tag": "my-own-in", "listen_port": 1080}],
  "outbounds": [{"type": "direct", "tag": "direct"}] }
J
    printf 'my own notes %s\n' "$SENTINEL" > "$SB/etc/sing-box/mynotes.txt"
  else
    # 本项目的数据模型(特征入站齐全)+ 可信归属标记
    cat > "$SB/etc/sing-box/config.json" <<'J'
{ "inbounds": [{"type":"direct","tag":"in-https","listen_port":443},
               {"type":"direct","tag":"in-http","listen_port":80},
               {"type":"mixed","tag":"tg-proxy","listen_port":8445}],
  "outbounds": [{"type":"direct","tag":"jp"}],
  "route": {"rules": [], "final": "jp"} }
J
    printf 'PDG-SINGBOX-OWNED v1\ncreated=2026-01-01T00:00:00Z\n' > "$SB/etc/privdns-gateway/singbox.pdg-owned"
  fi
  printf 'singbox\n' > "$SB/etc/privdns-gateway/backend"
  printf 'x\n' > "$SB/usr/local/bin/mihomo"
  printf 'log: {}\n' > "$SB/etc/mosdns/config.yaml"
  export SB
}

snap(){   # 第三方那几样东西的指纹
  {
    sha256sum "$SB/etc/systemd/system/sing-box.service" 2>/dev/null
    sha256sum "$SB/usr/local/bin/sing-box" 2>/dev/null
    find "$SB/etc/sing-box" -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null
  } | sha256sum | cut -d' ' -f1
}

# ── 归属判据本身 ────────────────────────────────────────────────────────────
. "$ROOT/lib/singbox.sh"
mk thirdparty
PDG_ROOT_PREFIX="$SB" pdg_singbox_is_ours \
  && bad "第三方(ExecStart 与 PDG 历史形态逐字一致)被误判为本项目所有" \
  || ok "判据: 仅凭标准 ExecStart 不认亲(第三方判为非本项目)"
mk pdg
PDG_ROOT_PREFIX="$SB" pdg_singbox_is_ours \
  && ok "判据: 有可信归属标记 → 认定本项目所有" || bad "自家(带标记)被判成第三方"
# 标记内容不可信(空文件/乱写)不算数
mk pdg; printf 'garbage\n' > "$SB/etc/privdns-gateway/singbox.pdg-owned"
PDG_ROOT_PREFIX="$SB" pdg_singbox_is_ours \
  && ok "无标记但配置是本项目数据模型+形态完整匹配 → 仍认定自家" \
  || bad "自家(数据模型齐全)被判成第三方"
# 形态完整匹配, 但 config.json 是别人的 → 不认亲
mk thirdparty; rm -f "$SB/etc/privdns-gateway/singbox.pdg-owned"
PDG_ROOT_PREFIX="$SB" pdg_singbox_is_ours \
  && bad "形态匹配但配置是第三方的, 仍被认成自家" || ok "判据: 形态匹配但配置非本项目 → 不认亲"

# ── uninstall / --purge ─────────────────────────────────────────────────────
run_uninstall(){
  # 生产里 uninstall.sh 与 lib/ 同在仓库根 —— 沙箱里也要照此摆放, 否则它找不到归属判据
  mkdir -p "$WORK/lib"; cp "$ROOT/lib/singbox.sh" "$WORK/lib/"
  sed -e "s#/etc/#$SB/etc/#g" -e "s#/usr/local/bin/#$SB/usr/local/bin/#g" \
      -e "s#/opt/pdg-bot#$SB/opt/pdg-bot#g" -e "s#/opt/privdns-gateway#$SB/opt/privdns-gateway#g" \
      -e "s#/var/lib/privdns-gateway#$SB/var/lib/privdns-gateway#g" \
      -e "s#/run/systemd/#$SB/run/systemd/#g" "$ROOT/uninstall.sh" > "$WORK/u.sh"
  sed -i -e "s#$SB/usr/local/bin/sing-box run -c $SB/etc/sing-box/config#/usr/local/bin/sing-box run -c /etc/sing-box/config#" "$WORK/u.sh"
  sed -i -e 's#^\[\[ \$EUID -eq 0 \]\].*#true#' "$WORK/u.sh"
  env SB="$SB" PDG_ROOT_PREFIX="$SB" bash -c "systemctl(){ :; }; nft(){ :; }; bash '$WORK/u.sh' ${1:-}" 2>&1
}

mk thirdparty; before="$(snap)"
run_uninstall >/dev/null
[[ "$(snap)" == "$before" ]] && ok "普通卸载: 第三方 unit/二进制/配置目录逐字节未变" || bad "普通卸载动了第三方文件"
grep -qF "$SENTINEL" "$SB/etc/sing-box/config.json" 2>/dev/null \
  && ok "普通卸载: 第三方 config.json 的 sentinel 仍在" || bad "第三方配置被改/被删"

mk thirdparty; before="$(snap)"
run_uninstall --purge >/dev/null
[[ "$(snap)" == "$before" ]] && ok "--purge: 第三方 unit/二进制/配置目录逐字节未变" || bad "--purge 动了第三方文件"
[[ -f "$SB/etc/sing-box/mynotes.txt" ]] \
  && ok "--purge: 第三方配置目录整体保留(未 rm -rf /etc/sing-box)" || bad "--purge 删了第三方配置目录"
grep -qF "$SENTINEL" "$SB/etc/sing-box/config.json" 2>/dev/null \
  && ok "--purge: sentinel 仍在" || bad "--purge 删/改了第三方配置"
[[ ! -e "$SB/usr/local/bin/mihomo" ]] \
  && ok "--purge: 项目自己的东西照删(保护没把卸载变成空操作)" || bad "mihomo 没删"

# 确属旧版 PDG 的 sing-box 仍要能清掉
mk pdg
run_uninstall --purge >/dev/null
{ [[ ! -e "$SB/etc/systemd/system/sing-box.service" ]] && [[ ! -e "$SB/usr/local/bin/sing-box" ]]; } \
  && ok "--purge: 确属旧版 PDG 的 sing-box 仍被正常清理" || bad "自家 sing-box 没清掉"

# ── 迁移路径 ────────────────────────────────────────────────────────────────
sed -n '/^pdg_singbox_is_ours(){/,/^}/p'   "$ROOT/lib/singbox.sh"    > "$WORK/fn.sh"
sed -n '/^pdg_singbox_mark_owned(){/,/^}/p' "$ROOT/lib/singbox.sh"  >> "$WORK/fn.sh"
sed -n '/^_pdg_drop_singbox_files(){/,/^}/p' "$ROOT/deploy/bot/pdg.sh" >> "$WORK/fn.sh"
mk thirdparty; before="$(snap)"
env SB="$SB" PDG_ROOT_PREFIX="$SB" bash -c "
c_g(){ echo \"\$*\"; }; c_y(){ echo \"\$*\"; }
systemctl(){ :; }
source '$WORK/fn.sh'
_pdg_drop_singbox_files 迁移" >/dev/null 2>&1
[[ "$(snap)" == "$before" ]] \
  && ok "迁移清理: 第三方 sing-box 逐字节未变" || bad "迁移清理动了第三方文件"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
