#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 端到端: 把一台"v1.4.x 时代的老机器"升到当前版本, 跑**真正的** pdg __migrate。
#
# 这条路线单测覆盖不到 —— 它是十几个迁移按顺序作用在同一份真实现场上的**累积结果**,
# 接缝正是出 bug 的地方(实践中查出的 GMS 重复插入、backend 标记从不落地, 都是这么发现的)。
#
# 老机器的特征: 无平台标记 / 无内核标记 / mosdns 是排除式老形态(无 hijack_set) /
# sing-box model 带 GMS 入站 / 用户加过显式出口规则 / iOS 组件装给了所有机器
# (v1.4.x 无平台概念, 所以它们的存在**证明不了**平台)。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
E2E_ROOT="${E2E_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=tests/e2e-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/e2e-lib.sh"
e2e_enter "$@"

e2e_stub_system
e2e_seed_install

seed_old_box(){   # $1=平台标记(留空=老机器原样, 无标记)
  rm -f /etc/privdns-gateway/platform /etc/privdns-gateway/platform.guessed /etc/privdns-gateway/backend
  e2e_seed_mosdns all
  # 回到 pre-profile / pre-schema 版本：仅保留当时已有的两个 profile 键，
  # 并制造 nftscan.py 明确认得出的精确 markerless stock PDG 形态。新版迁移
  # 必须从这些已部署证据补齐 firewall mode、CIDR、SSH 与 QUIC 数据面契约。
  /usr/local/libexec/pdg-quic-routing.sh remove >/dev/null 2>&1 || true
  rm -f /etc/privdns-gateway/firewall-mode /etc/privdns-gateway/quic-routing.state
  rm -f /usr/local/libexec/pdg-quic-routing.sh \
        /etc/systemd/system/pdg-quic-routing.service
  printf 'PDG_LOWMEM=0\nPDG_HIJACK_MODE=all\n' > /etc/privdns-gateway/profile.env
  echo 0 > /tmp/e2e-svc/pdg-quic-routing.ac
  echo 0 > /tmp/e2e-svc/pdg-quic-routing.en
  cat > /etc/nftables.conf <<'NFT'
#!/usr/sbin/nft -f
table inet pdg
delete table inet pdg

table inet pdg {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip saddr 127.0.0.0/8 tcp dport { 80, 443, 5228-5230 } redirect to :7893
    }
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        tcp dport { 22 } accept
        ip saddr 127.0.0.0/8 tcp dport { 53, 81, 853, 7893, 8445 } accept
        ip saddr 127.0.0.0/8 udp dport 53 accept
        ip saddr 127.0.0.0/8 udp dport 443 reject
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
    }
}
NFT
  # 退回"老形态": 去掉 hijack_set 插件(那时还没有这机制)
  python3 - /etc/mosdns/config.yaml <<'PY'
import re, sys
f = sys.argv[1]; s = open(f, encoding="utf-8").read()
s = re.sub(r"  # custom_hijack[\s\S]*?(?=  - tag: force_hijack)", "", s)
s = re.sub(r"  - tag: hijack_set\n    type: domain_set\n    args: \{[^\n]*\n", "", s)
open(f, "w", encoding="utf-8").write(s)
PY
  # v1.4.x 的 model: GMS 入站 + 用户加过的显式出口规则
  cat > /etc/sing-box/config.json <<'J'
{"log":{"level":"warn"},
 "inbounds":[{"type":"direct","tag":"in-http","listen":"0.0.0.0","listen_port":80,"sniff":true,"sniff_override_destination":true},
             {"type":"direct","tag":"in-https","listen":"0.0.0.0","listen_port":443,"sniff":true,"sniff_override_destination":true},
             {"type":"direct","tag":"in-gms-5228","listen":"0.0.0.0","listen_port":5228,"sniff":true,"sniff_override_destination":true},
             {"type":"direct","tag":"in-gms-5229","listen":"0.0.0.0","listen_port":5229,"sniff":true,"sniff_override_destination":true},
             {"type":"direct","tag":"in-gms-5230","listen":"0.0.0.0","listen_port":5230,"sniff":true,"sniff_override_destination":true}],
 "outbounds":[{"type":"direct","tag":"direct"},
              {"type":"shadowsocks","tag":"jp","server":"198.51.100.7","server_port":8388,"method":"aes-128-gcm","password":"x"}],
 "route":{"rules":[{"action":"reject","ip_cidr":["203.0.113.1/32"]},
                   {"domain_suffix":["ip.skk.moe","example.test"],"outbound":"jp"}],
          "final":"direct"}}
J
  # 当时由 PDG 安装且仍在运行的 sing-box runtime。可信归属标记与历史
  # unit 形态让迁移真正覆盖 stop/disable/read-back/remove 生命周期。
  cat > /usr/local/bin/sing-box <<'SB'
#!/bin/sh
exit 0
SB
  chmod 755 /usr/local/bin/sing-box
  cat > /etc/systemd/system/sing-box.service <<'SBU'
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
SBU
  : > /etc/privdns-gateway/singbox.pdg-owned
  echo 1 > /tmp/e2e-svc/sing-box.ac
  echo 1 > /tmp/e2e-svc/sing-box.en
  echo 0 > /tmp/e2e-svc/mihomo.ac
  echo 0 > /tmp/e2e-svc/mihomo.en
  # v1.4.x 把 iOS 组件装给所有机器 → 它们证明不了平台
  install -m644 "$E2E_ROOT/deploy/ios/pdg-dot-ondemand.mobileconfig.tmpl" /opt/pdg-bot/pdg-dot.mobileconfig.tmpl
  install -m755 "$E2E_ROOT/deploy/ios/probe81.py" /opt/pdg-bot/probe81.py
  : > /etc/systemd/system/pdg-probe81.service
  [[ -n "${1:-}" ]] && printf '%s\n' "$1" > /etc/privdns-gateway/platform
  return 0
}
gms(){ grep -c 'in-gms-52' /etc/sing-box/config.json; }
plug(){ grep -c 'tag: hijack_set' /etc/mosdns/config.yaml; }
gate(){ grep -c '!qname \$hijack_set' /etc/mosdns/config.yaml; }

# ══ 场景一: 老机器原样(无任何平台证据) ══════════════════════════════════════
echo "── 场景一: v1.4.x 老机器, 无平台/内核标记 ──"
seed_old_box
[[ "$(plug)" == 0 && "$(gms)" == 3 ]] || bad "前置: 老形态没造对"
bash /usr/local/bin/pdg __migrate >/tmp/mig1.log 2>&1
rc=$?
[[ "$rc" == 0 ]] && ok "迁移整体成功(exit 0)" || bad "迁移退出码 $rc: $(tail -3 /tmp/mig1.log)"

# 平台: 无证据 → 推测 android, 且**不做破坏性清理**
{ [[ "$(cat /etc/privdns-gateway/platform)" == android ]] && [[ -e /etc/privdns-gateway/platform.guessed ]]; } \
  && ok "无证据 → 平台回退 android 且标记为推测" || bad "平台推测标记缺失"
{ [[ -e /opt/pdg-bot/probe81.py ]] && [[ -e /etc/systemd/system/pdg-probe81.service ]] \
  && [[ -e /opt/pdg-bot/pdg-dot.mobileconfig.tmpl ]]; } \
  && ok "推测态: iOS 组件一个没删(万一这台其实服务 iPhone)" || bad "推测态下 iOS 组件被删了"
grep -q '跳过 iOS 组件清理' /tmp/mig1.log && ok "推测态: 明确说明跳过了清理" || bad "未提示跳过清理"

# v1.6.0: 老装(sing-box)迁移后内核标记必须落定 mihomo, 且 sing-box 运行时被清干净
[[ "$(cat /etc/privdns-gateway/backend 2>/dev/null)" == mihomo ]] \
  && ok "老装迁移: 内核标记落定 mihomo" || bad "backend=$(cat /etc/privdns-gateway/backend 2>/dev/null)"
{ [[ ! -e /etc/systemd/system/sing-box.service ]] && [[ ! -e /usr/local/bin/sing-box ]]; } \
  && ok "老装迁移: sing-box unit 与二进制已移除" || bad "sing-box 运行时仍有残留"
grep -q 'sing-box 运行时已移除' /tmp/mig1.log \
  && ok "老装迁移: 迁移过程有明确告知" || bad "迁移日志未提到移除 sing-box"

# mosdns: 补 hijack_set 插件, all 模式不装劫持门
{ [[ "$(plug)" == 1 ]] && [[ "$(gate)" == 0 ]]; } \
  && ok "mosdns: 补上 hijack_set 插件, all 仍是排除式(不装劫持门)" || bad "劫持形态错: 插件=$(plug) 门=$(gate)"

# 用户此前加过的显式出口域名必须被回填进劫持表(否则那些规则一直是死的)
hj=$(grep -c '^domain:' /etc/mosdns/rules/custom_hijack.txt 2>/dev/null || echo 0)
{ [[ "$hj" == 2 ]] && grep -q 'ip.skk.moe' /etc/mosdns/rules/custom_hijack.txt; } \
  && ok "回填: 已有的显式出口域名进了劫持表(用户无需重加)" || bad "回填数=$hj"

# GMS: android 平台该保留, 且不得重复插入
[[ "$(gms)" == 3 ]] && ok "GMS 入站保持 3 条(android 需要, 且未重复插入)" || bad "GMS 入站变成 $(gms) 条"

# 幂等
cp /etc/mosdns/config.yaml /tmp/m1; cp /etc/sing-box/config.json /tmp/s1
bash /usr/local/bin/pdg __migrate >/tmp/mig2.log 2>&1
{ cmp -s /tmp/m1 /etc/mosdns/config.yaml && cmp -s /tmp/s1 /etc/sing-box/config.json; } \
  && ok "二跑幂等(mosdns 与 model 均无变化)" || bad "二跑改动了配置"

# ══ 场景二: 平台已确认 ios ══════════════════════════════════════════════════
echo; echo "── 场景二: 同样的老机器, 但平台已确认 ios ──"
seed_old_box ios
bash /usr/local/bin/pdg __migrate >/tmp/mig3.log 2>&1
[[ "$(gms)" == 0 ]] && ok "iOS: GMS 入站被清理干净(iOS 走 APNs 用不到)" || bad "iOS 仍有 $(gms) 条 GMS 入站"
{ [[ -e /opt/pdg-bot/probe81.py ]] && [[ -e /etc/systemd/system/pdg-probe81.service ]]; } \
  && ok "iOS: iOS 组件保留" || bad "iOS 组件被误删"
[[ ! -e /etc/privdns-gateway/platform.guessed ]] && ok "iOS: 已确认平台不打推测标记" || bad "已确认平台仍被当成推测"
[[ -e /etc/systemd/system/pdg-mitm.service ]] && ok "iOS: 补上 pdg-mitm 服务(MITM 插件宿主)" || bad "缺 pdg-mitm unit"
cp /etc/sing-box/config.json /tmp/s2
bash /usr/local/bin/pdg __migrate >/dev/null 2>&1
cmp -s /tmp/s2 /etc/sing-box/config.json && ok "iOS: 二跑幂等" || bad "iOS 二跑改动了 model"

# ══ 场景三: 已是新形态 + gfw 模式 → 劫持门必须保留 ═══════════════════════════
echo; echo "── 场景三: 新形态 + gfw 模式 ──"
rm -f /etc/privdns-gateway/platform.guessed
printf 'android\n' > /etc/privdns-gateway/platform
e2e_seed_mosdns gfw
bash /usr/local/bin/pdg __migrate >/dev/null 2>&1
{ [[ "$(gate)" == 2 ]] && grep -q 'geosite_gfw.txt' /etc/mosdns/config.yaml; } \
  && ok "gfw 模式: 劫持门保留且指向 gfw 劫持集(迁移不把它当 all 拆掉)" || bad "gfw 门=$(gate)"

e2e_summary
