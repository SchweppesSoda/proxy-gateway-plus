#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 端到端: 真的把一台"仍在跑 sing-box 的老机器"迁到 mihomo(v1.6.0 移除 sing-box 运行时)。
# 取**真** mihomo 二进制、真实协议出口, 走真正的 migrate_drop_singbox / _activate_mihomo_core,
# 用真 `mihomo -t` 校验渲染产物。
#
# 单测只能打桩 activate/restore 与渲染, "这些出口到底转不转得过去"全靠真内核说了算 ——
# 而迁移一旦丢出口就是线上事故(用户的落地节点凭空少一个), 故必须端到端验一遍。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
E2E_ROOT="${E2E_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=tests/e2e-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/e2e-lib.sh"
e2e_enter "$@"

e2e_stub_system
e2e_seed_install
e2e_seed_mosdns all
e2e_seed_singbox_model
e2e_seed_nft
printf 'android\n' > /etc/privdns-gateway/platform
# 老机器现场: backend 仍是 singbox, sing-box 二进制 + unit 都在
printf 'singbox\n' > /etc/privdns-gateway/backend
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/sing-box; chmod 755 /usr/local/bin/sing-box
printf '[Unit]\nDescription=sing-box\n' > /etc/systemd/system/sing-box.service

e2e_fetch_mihomo || e2e_skip "取不到 mihomo 二进制"
echo "内核: $(mihomo -v 2>&1 | head -1)"

# 先加几个真实协议出口 —— 迁移最容易翻车的正是"某协议转不过去"
python3 - >/dev/null 2>&1 <<'PY'
import base64, sys; sys.path.insert(0, "/opt/pdg-bot")
import bot
ssb = base64.b64encode(b"aes-128-gcm:secret123").decode().rstrip("=")
for link in ("ss://%s@5.6.7.8:8388#e-ss" % ssb,
             "trojan://tjpass@t.example.com:443?sni=t.example.com#e-trojan",
             "hysteria2://pw@h2.example.com:8443?sni=h2.example.com&insecure=1#e-hy2"):
    ob = bot.parse_link(link)
    def mod(c, ob=ob):
        c["outbounds"] = [o for o in c["outbounds"] if o.get("tag") != ob["tag"]]
        c["outbounds"].append(ob)
    bot.apply_sb(mod)
PY
n=$(python3 -c "import json;print(len([o for o in json.load(open('/etc/sing-box/config.json'))['outbounds'] if o.get('tag','').startswith('e-')]))")
[[ "$n" == 3 ]] && ok "前置: 3 个真实协议出口就位" || bad "前置只有 $n 个出口"

# ══ 1. 有出口转不过去 → 迁移必须拒绝、点名、且不动 sing-box 运行时 ════════════
# (先测失败路径: 此时机器还完整, 正好验"失败不留半迁移态")
echo; echo "── 1. 注入一个 mihomo 转不了的出口 → 迁移应拒绝 ──"
python3 - <<'PY' >/dev/null 2>&1
import json
f = "/etc/sing-box/config.json"; c = json.load(open(f))
c["outbounds"].append({"type": "wireguard", "tag": "e-wg-unsupported",
                       "server": "wg.example.com", "server_port": 51820,
                       "private_key": "aaaa", "peer_public_key": "bbbb", "local_address": ["10.0.0.2/32"]})
json.dump(c, open(f, "w"), ensure_ascii=False, indent=2)
PY
out=$(bash /usr/local/bin/pdg __migrate 2>&1); rc=$?
if [[ "$rc" != 0 ]]; then
  ok "转换不了 → 迁移返回非0(据此让 pdg update 回滚到更新前快照)"
  grep -q 'e-wg-unsupported' <<<"$out" \
    && ok "并**点名**是哪个出口转不了(不再只说'渲染/校验失败')" \
    || bad "没点名具体出口: $(tail -3 <<<"$out")"
  [[ "$(cat /etc/privdns-gateway/backend)" == singbox ]] \
    && ok "拒绝后 backend 标记已回滚" || bad "标记没回滚"
  { [[ -e /usr/local/bin/sing-box ]] && [[ -e /etc/systemd/system/sing-box.service ]]; } \
    && ok "拒绝后 sing-box 运行时原样保留(用户仍能用旧版, 无半迁移态)" || bad "sing-box 被误删"
else
  bad "wireguard 出口应被判为无法转换并拒绝迁移, 实际却迁成功了(它会被静默丢弃)"
fi

# ══ 2. 去掉那个出口 → 迁移应成功, 3 个真实出口一个不少 ═══════════════════════
echo; echo "── 2. 移除不可转换出口 → 迁移应成功 ──"
python3 - <<'PY' >/dev/null 2>&1
import json
f = "/etc/sing-box/config.json"; c = json.load(open(f))
c["outbounds"] = [o for o in c["outbounds"] if o.get("tag") != "e-wg-unsupported"]
json.dump(c, open(f, "w"), ensure_ascii=False, indent=2)
PY
out=$(bash /usr/local/bin/pdg __migrate 2>&1); rc=$?
{ [[ "$rc" == 0 ]] && grep -q 'sing-box 运行时已移除' <<<"$out"; } \
  && ok "迁移成功(3 个协议全部转换通过)" || bad "迁移失败 rc=$rc: $(tail -4 <<<"$out")"
[[ "$(cat /etc/privdns-gateway/backend)" == mihomo ]] && ok "backend 标记 → mihomo" || bad "标记未切"
mihomo -t -d /etc/mihomo -f /etc/mihomo/config.yaml >/dev/null 2>&1 \
  && ok "真 mihomo -t 接受迁移后的配置" || bad "迁移后的 mihomo 配置校验不过"
python3 -c "
import json,sys
d=json.load(open('/etc/mihomo/config.yaml'))
names={p['name'] for p in d.get('proxies',[])}
sys.exit(0 if {'e-ss','e-trojan','e-hy2'} <= names else 1)" \
  && ok "三个出口都在 mihomo 配置里(迁移没有凭空丢失)" || bad "迁移后出口丢失"
{ [[ ! -e /usr/local/bin/sing-box ]] && [[ ! -e /etc/systemd/system/sing-box.service ]]; } \
  && ok "sing-box 二进制与 unit 已彻底移除" || bad "sing-box 运行时仍有残留"
grep -q 'redirect' /etc/nftables.conf \
  && ok "防火墙已换成 mihomo 的 REDIRECT 入站模型" || bad "nft 未切到 mihomo 变体"

# ══ 3. 幂等: 已是纯 mihomo 再迁一次 → 直接过, 不重复动内核 ═══════════════════
echo; echo "── 3. 幂等 ──"
out=$(bash /usr/local/bin/pdg __migrate 2>&1); rc=$?
{ [[ "$rc" == 0 ]] && ! grep -q '检测到 sing-box 运行时' <<<"$out"; } \
  && ok "已是纯 mihomo → 迁移短路(不重复迁)" || bad "二次迁移未短路 rc=$rc: $(tail -3 <<<"$out")"
mihomo -t -d /etc/mihomo -f /etc/mihomo/config.yaml >/dev/null 2>&1 \
  && ok "二跑后配置仍合法" || bad "二跑把配置搞坏了"

e2e_summary
