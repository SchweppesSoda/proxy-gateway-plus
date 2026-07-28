#!/bin/bash
# certbot --standalone post-hook: 还原完整 profile-owned data plane。
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
    "$NFT" -f /etc/nftables.conf
elif command -v iptables >/dev/null 2>&1; then
    while iptables -D INPUT -p tcp --dport 80 -m comment --comment proxy-gateway-cert-http -j ACCEPT 2>/dev/null; do :; done
fi
# Re-applying nft alone is insufficient in native QUIC mode.  The helper uses
# strict state provenance and exact rule/route status; failure is propagated to
# certbot instead of silently leaving TCP restored but QUIC broken.
QUIC=/usr/local/libexec/pdg-quic-routing.sh
[[ -x "$QUIC" ]]
"$QUIC" apply
"$QUIC" status >/dev/null
# Mihomo is never stopped by the current pre-hook.
exit 0
