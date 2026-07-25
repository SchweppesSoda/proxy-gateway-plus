#!/usr/bin/env bash
# 卸载 PrivDNS Gateway (保留 certbot 证书与二进制; 加 --purge 一并删)。
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "请用 root 运行"; exit 1; }

# sing-box 归属判定: v1.6 起本项目不再装 sing-box, 但老机器上可能仍有一份。机器上那份未必
# 是我们装的(用户完全可能自己跑一个干别的) —— 删别人的东西不可逆, 故只删能证明是本项目装的。
# 判据集中在 lib/singbox.sh(与 pdg / install 共用): 可信归属标记, 或"完整匹配历史 PDG unit
# 形态 + 现场另有本项目特征"。单凭一条 ExecStart 不算数 —— 那正是手工安装最常见的写法。
SB_UNIT=/etc/systemd/system/sing-box.service
SB_OWNED=0
SB_WHY="(未判定)"
_UN_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo .)"
if [[ -f "$_UN_HERE/lib/singbox.sh" ]]; then
  # shellcheck source=lib/singbox.sh
  source "$_UN_HERE/lib/singbox.sh"
  pdg_singbox_is_ours "$SB_UNIT" && SB_OWNED=1
  # 原因要在 --purge 动手**之前**问出来: backend 标记等判据文件待会儿就被删了, 事后再问,
  # 报出来的会是"缺 backend"这种由卸载自己造成的假原因。
  [[ "$SB_OWNED" == 0 ]] && SB_WHY="$(pdg_singbox_why_not_ours "$SB_UNIT")"
else
  echo "警告: 找不到 lib/singbox.sh, 无法判定 sing-box 归属 → 一律保留(不删)。"
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
# 归属证明不了 → 全保留。但不能只丢一句"已保留": 用户手工改过 unit 的情况下也会走到这里,
# 机器上从此挂着一个没人管的 sing-box。逐条列出留了什么、为什么判不出来、怎么自己清。
_sb_report_kept(){   # $1=with-config(--purge 时连配置目录一起列)
  local kept; kept="$(pdg_singbox_kept_paths "${1:-}")"
  [[ -n "$kept" ]] || return 0
  echo "注意: 以下 sing-box 文件无法确认是本项目安装的 → 已原样保留:"
  printf '%s\n' "$kept" | sed 's/^/    /'
  echo "  判不出归属的原因: $SB_WHY"
  echo "  确认它无用可自行清理:"
  echo "    systemctl disable --now sing-box"
  echo "    rm -rf $(printf '%s' "$kept" | tr '\n' ' ')"
}
[[ "$SB_OWNED" == 0 && "${1:-}" != "--purge" ]] && declare -F pdg_singbox_kept_paths >/dev/null \
  && _sb_report_kept

if [[ "${1:-}" == "--purge" ]]; then
  echo "[--purge] 删除配置与数据…"
  rm -rf /etc/mosdns /etc/mihomo /opt/pdg-bot /etc/privdns-gateway   # /etc/privdns-gateway 含 bot.env(token) + CA 私钥
  # /etc/sing-box 平时是本项目的数据模型目录(config.json/rs/ui) —— 但**只有确认 sing-box 属于
  # 本项目时才敢删**: 证明不了归属就说明这台机器上的 sing-box 是别人的, 那这个目录里放的多半
  # 也是别人的配置, 删掉不可逆。
  [[ "$SB_OWNED" == 1 ]] && rm -rf /etc/sing-box
  rm -f /usr/local/bin/mosdns /usr/local/bin/mihomo \
        /usr/local/bin/pdg /usr/local/bin/pdg-set-token \
        /usr/local/bin/proxy-gateway-open-cert-http.sh \
        /usr/local/bin/proxy-gateway-restore-firewall.sh \
        /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
  # sing-box 二进制同样只删本项目装的; 来源不明的留给用户自己处置
  [[ "$SB_OWNED" == 1 ]] && rm -f /usr/local/bin/sing-box
  # 保留清单(unit / 二进制 / 整个 /etc/sing-box)一次性报全, 不散在各处只提一句
  [[ "$SB_OWNED" == 0 ]] && declare -F pdg_singbox_kept_paths >/dev/null \
    && _sb_report_kept with-config
  rm -rf /opt/privdns-gateway /var/lib/privdns-gateway   # 仓库副本 + 快照 (放最后, 脚本已载入内存, 删它安全)
  echo "已 purge。证书目录 /etc/letsencrypt 仍保留(含账户), 如需彻底清除请手动 certbot delete。"
fi
