#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# GMS 推送端口契约回归。
#
# 当前实现由 canonical platform profile 集中决定 TLS 劫持端口，再由统一 renderer 同时
# 生成 nft set / REDIRECT 数据面；不允许迁移函数用 sed 二次修改生成产物。历史入口
# migrate_fw_gms 仅为跨版本调用兼容而保留，必须是逐字节 no-op。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# 抽出 legacy 兼容入口。
eval "$(sed -n '/^migrate_fw_gms(){/,/^}/p' "$ROOT/deploy/bot/pdg.sh")"

pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

# ── canonical profile: Android 补齐 GMS，renderer 只从 nft set 引用 ────────
cat >"$WORK/profile.env" <<'EOF'
PDG_FIREWALL_MODE=managed
PDG_PLATFORM=ios
PDG_INTERNAL_CIDR=172.22.0.0/16
PDG_SSH_PORT=22
PDG_QUIC_MODE=tproxy
PDG_HIJACK_TLS_TCP_PORTS=443,10443
PDG_HIJACK_HTTP_TCP_PORTS=80
PDG_QUIC_MARK=0x504447
PDG_QUIC_MARK_MASK=0xffffffff
PDG_QUIC_ROUTE_TABLE=7895
PDG_QUIC_RULE_PRIORITY=17895
EOF

python3 "$ROOT/deploy/bot/pdgprofile.py" \
  --profile "$WORK/profile.env" retarget-platform android >"$WORK/android.env"
mv "$WORK/android.env" "$WORK/profile.env"
grep -qxF 'PDG_PLATFORM=android' "$WORK/profile.env" \
  && grep -qxF 'PDG_HIJACK_TLS_TCP_PORTS=443,5228,5229,5230,10443' "$WORK/profile.env" \
  && ok "切到 Android → canonical profile 补齐 GMS 且保留自定义 TLS 端口" \
  || bad "Android profile 未集中写入 GMS 端口"

python3 "$ROOT/deploy/bot/pdgprofile.py" \
  --profile "$WORK/profile.env" --platform android --ssh-port 22 --profile-only \
  render-nft --template "$ROOT/deploy/firewall/nftables-mihomo.conf" \
  --internal-cidr 172.22.0.0/16 --firewall-mode managed >"$WORK/android.nft"
grep -Fq 'elements = { 443, 5228, 5229, 5230, 10443 }' "$WORK/android.nft" \
  && grep -Fq 'tcp dport @pdg_tls_tcp_ports redirect to :7893' "$WORK/android.nft" \
  && ok "Android renderer → GMS 位于 canonical TLS set 并由统一 REDIRECT 引用" \
  || bad "Android renderer 未从 profile 生成 GMS TLS set"

# ── canonical profile: iOS 去除 GMS，renderer 随 profile 收敛 ─────────────
python3 "$ROOT/deploy/bot/pdgprofile.py" \
  --profile "$WORK/profile.env" retarget-platform ios >"$WORK/ios.env"
mv "$WORK/ios.env" "$WORK/profile.env"
python3 "$ROOT/deploy/bot/pdgprofile.py" \
  --profile "$WORK/profile.env" --platform ios --ssh-port 22 --profile-only \
  render-nft --template "$ROOT/deploy/firewall/nftables-mihomo.conf" \
  --internal-cidr 172.22.0.0/16 --firewall-mode managed >"$WORK/ios.nft"
grep -qxF 'PDG_HIJACK_TLS_TCP_PORTS=443,10443' "$WORK/profile.env" \
  && grep -Fq 'elements = { 443, 10443 }' "$WORK/ios.nft" \
  && ! grep -Eq '5228|5229|5230' "$WORK/ios.nft" \
  && ok "切到 iOS → profile/renderer 一致去除 GMS，保留通用 TLS 端口" \
  || bad "iOS profile/renderer 仍有 GMS 漂移"

# ── legacy 入口: 兼容调用成功，但任何形态都不得再 sed 改写 ───────────────
cat >"$WORK/legacy.nft" <<'EOF'
table inet pdg {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip saddr 172.22.0.0/16 tcp dport { 80, 443 } redirect to :7893
    }
}
EOF
cp -a "$WORK/legacy.nft" "$WORK/legacy.before"
migrate_fw_gms "$WORK/legacy.nft"
rc=$?
[[ "$rc" == 0 ]] && cmp -s "$WORK/legacy.before" "$WORK/legacy.nft" \
  && ok "legacy migrate_fw_gms → 兼容 no-op，文件逐字节不变" \
  || bad "legacy migrate_fw_gms 仍改写生成产物或返回失败"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
