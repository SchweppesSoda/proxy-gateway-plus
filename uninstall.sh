#!/usr/bin/env bash
# 卸载 PrivDNS Gateway (保留 certbot 证书与二进制; 加 --purge 一并删)。
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "请用 root 运行"; exit 1; }

# sing-box 归属判定: v1.6 起本项目不再装 sing-box, 但老机器上可能仍有一份。机器上那份未必
# 是我们装的(用户完全可能自己跑一个干别的) —— 删别人的东西不可逆, 故只删能证明是本项目装的。
# 判据与 pdg 的 _pdg_singbox_is_ours 一致: 归属标记, 或 unit 是老版 pdg_unit_singbox 的形态。
SB_UNIT=/etc/systemd/system/sing-box.service
SB_OWNED=0
if [[ -e /etc/privdns-gateway/singbox.pdg-owned ]]; then SB_OWNED=1
elif [[ -f "$SB_UNIT" ]] \
     && grep -qE '^ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config\.json([[:space:]]|$)' "$SB_UNIT"; then
  SB_OWNED=1
fi

systemctl disable --now pdg-bot pdg-probe81 mosdns mihomo pdg-mitm pdg-rules-update.timer pdg-health.timer 2>/dev/null || true
[[ "$SB_OWNED" == 1 ]] && systemctl disable --now sing-box 2>/dev/null || true
rm -f /etc/systemd/system/{pdg-bot,pdg-probe81,mosdns,mihomo,pdg-mitm,pdg-rules-update,pdg-health}.service \
      /etc/systemd/system/pdg-rules-update.timer /etc/systemd/system/pdg-health.timer \
      /etc/systemd/journald.conf.d/50-pdg.conf /etc/systemd/system/journald.conf.d/50-pdg.conf   # 正确路径 + 历史错路径都删
[[ "$SB_OWNED" == 1 ]] && rm -f "$SB_UNIT"
systemctl daemon-reload
systemctl restart systemd-journald 2>/dev/null || true   # journald CanReload=no, 必须 restart 才会松开封顶

# 防火墙: 删本项目独立表 inet pdg(不碰 Docker/fail2ban 等其它表); 有备份则还原 /etc/nftables.conf
command -v nft >/dev/null 2>&1 && nft delete table inet pdg 2>/dev/null || true
if [[ -e /etc/nftables.conf.pdg-orig ]]; then
  mv -f /etc/nftables.conf.pdg-orig /etc/nftables.conf
  nft -f /etc/nftables.conf 2>/dev/null || true
fi
# DNS: 还原 systemd-resolved 与 resolv.conf
systemctl list-unit-files 2>/dev/null | grep -q '^systemd-resolved' && systemctl enable --now systemd-resolved 2>/dev/null || true
if [[ -e /etc/resolv.conf.pdg-orig ]]; then
  rm -f /etc/resolv.conf; mv /etc/resolv.conf.pdg-orig /etc/resolv.conf
elif [[ -e /run/systemd/resolve/stub-resolv.conf ]]; then
  ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fi

echo "已停止并移除 systemd 单元、防火墙表(inet pdg)、并尽量还原 DNS。"
echo "保留: /etc/mosdns /etc/sing-box /etc/mihomo /opt/pdg-bot 与 Let's Encrypt 证书。"
[[ "$SB_OWNED" == 0 && -e "$SB_UNIT" ]] && \
  echo "注意: /etc/systemd/system/sing-box.service 无法确认是本项目安装的 → 已保留未动。"

if [[ "${1:-}" == "--purge" ]]; then
  echo "[--purge] 删除配置与数据…"
  # /etc/sing-box 是本项目的数据模型目录(config.json/rs/ui), 与"第三方 sing-box 程序"无关, 照删。
  rm -rf /etc/mosdns /etc/sing-box /etc/mihomo /opt/pdg-bot /etc/privdns-gateway   # /etc/privdns-gateway 含 bot.env(token) + CA 私钥
  rm -f /usr/local/bin/mosdns /usr/local/bin/mihomo \
        /usr/local/bin/pdg /usr/local/bin/pdg-set-token \
        /usr/local/bin/proxy-gateway-open-cert-http.sh \
        /usr/local/bin/proxy-gateway-restore-firewall.sh \
        /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
  # sing-box 二进制同样只删本项目装的; 来源不明的留给用户自己处置
  if [[ "$SB_OWNED" == 1 ]]; then
    rm -f /usr/local/bin/sing-box
  elif [[ -e /usr/local/bin/sing-box ]]; then
    echo "[--purge] /usr/local/bin/sing-box 无法确认是本项目安装的 → 已保留(如确认无用请自行删除)。"
  fi
  rm -rf /opt/privdns-gateway /var/lib/privdns-gateway   # 仓库副本 + 快照 (放最后, 脚本已载入内存, 删它安全)
  echo "已 purge。证书目录 /etc/letsencrypt 仍保留(含账户), 如需彻底清除请手动 certbot delete。"
fi
