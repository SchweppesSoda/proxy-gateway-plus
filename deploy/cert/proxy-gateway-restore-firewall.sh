#!/bin/bash
# certbot --standalone post-hook: 还原防火墙 + (sing-box 模式)把 80 口还给 sing-box。
set -e
# nft 位置同 pre-hook, 走共用判据(lib/nftbin.sh): PATH 里没有 sbin 时若落到 iptables 分支,
# pre-hook 插进 nft 的那条 80 口放行就永远撤不掉了。
NFT=""
if [[ -f /opt/privdns-gateway/lib/nftbin.sh ]]; then
    # shellcheck source=../../lib/nftbin.sh
    . /opt/privdns-gateway/lib/nftbin.sh && NFT="$(pdg_nft_bin || true)"
fi
[[ -n "$NFT" ]] || NFT="$(command -v nft 2>/dev/null || true)"
if [[ -n "$NFT" ]] && [[ -f /etc/nftables.conf ]]; then
    "$NFT" -f /etc/nftables.conf 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
    while iptables -D INPUT -p tcp --dport 80 -m comment --comment proxy-gateway-cert-http -j ACCEPT 2>/dev/null; do :; done
fi
CORE=$(cat /etc/privdns-gateway/backend 2>/dev/null || echo singbox)
[[ "$CORE" == singbox ]] && { systemctl start sing-box 2>/dev/null || true; }
# mihomo 模式: 全程没停 mihomo, 无需启动
exit 0
