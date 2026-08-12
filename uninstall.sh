#!/usr/bin/env bash
# 卸载 PrivDNS Gateway (保留 certbot 证书与二进制; 加 --purge 一并删)。
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "请用 root 运行"; exit 1; }

# sing-box 归属判定: v1.6 起本项目不再装 sing-box, 但老机器上可能仍有一份。机器上那份未必
# 是我们装的(用户完全可能自己跑一个干别的) —— 删别人的东西不可逆, 故只删能证明是本项目装的。
# 判据集中在 lib/singbox.sh(与 pdg / install 共用): 可信归属标记, 或"完整匹配历史 PDG unit
# 形态 + 现场另有本项目特征"。单凭一条 ExecStart 不算数 —— 那正是手工安装最常见的写法。
# 运行时归属(unit/二进制)与**数据模型归属**(/etc/sing-box 目录)是两回事: v1.6 起本项目根本
# 不装 sing-box 运行时, 于是运行时归属恒为否 —— 但 /etc/sing-box/config.json 仍是本项目的数据
# 模型, 里面是出口密码、UUID、节点地址。拿运行时归属决定 purge 删不删这个目录, 纯 mihomo 的
# 新装机器 purge 完凭据还原样躺在盘上。两者分开判。
SB_UNIT=/etc/systemd/system/sing-box.service
SB_OWNED=0
SB_WHY="(未判定)"
MODEL_OWNED=0
MODEL_WHY="(未判定)"
_UN_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo .)"
if [[ -f "$_UN_HERE/lib/singbox.sh" ]]; then
  # shellcheck source=lib/singbox.sh
  source "$_UN_HERE/lib/singbox.sh"
  pdg_singbox_is_ours "$SB_UNIT" && SB_OWNED=1
  # 原因要在 --purge 动手**之前**问出来: backend 标记等判据文件待会儿就被删了, 事后再问,
  # 报出来的会是"缺 backend"这种由卸载自己造成的假原因。
  [[ "$SB_OWNED" == 0 ]] && SB_WHY="$(pdg_singbox_why_not_ours "$SB_UNIT")"
  pdg_sbmodel_is_ours && MODEL_OWNED=1
  [[ "$MODEL_OWNED" == 0 ]] && MODEL_WHY="$(pdg_sbmodel_why_not_ours)"
else
  echo "警告: 找不到 lib/singbox.sh, 无法判定 sing-box 归属 → 一律保留(不删)。"
fi

# QUIC policy routing is not discoverable ownership: an exact-looking fwmark
# rule may belong to somebody else.  Stop/apply cleanup while the strict state,
# profile parser and helper still exist.  Missing/corrupt state never grants
# authority to delete a tuple; on any uncertainty preserve all recovery files.
QUIC_WARN="" QUIC_CLEAN=0 _UN_QUIC=""
for _p in /usr/local/libexec/pdg-quic-routing.sh \
          "$_UN_HERE/deploy/firewall/pdg-quic-routing.sh"; do
  [[ -f "$_p" ]] && { _UN_QUIC="$_p"; break; }
done
systemctl stop pdg-quic-routing 2>/dev/null || true
systemctl disable pdg-quic-routing 2>/dev/null || true
if [[ -n "$_UN_QUIC" ]]; then
  if bash "$_UN_QUIC" remove >/dev/null 2>&1 \
    && bash "$_UN_QUIC" cleanup-status >/dev/null 2>&1 \
    && [[ ! -e /etc/privdns-gateway/quic-routing.state ]]; then
    QUIC_CLEAN=1
  else
    QUIC_WARN="可信 QUIC route/rule 未能精确清理；state/profile/helper 均已保留供恢复。"
  fi
elif [[ -e /etc/privdns-gateway/quic-routing.state ]]; then
  QUIC_WARN="存在 QUIC routing state 但 helper 缺失；未猜测删除任何 route/rule，恢复文件已保留。"
else
  QUIC_WARN="QUIC helper 与可信 state 均缺失，无法只读证明 profile tuple 未占用；未删除任何 route/rule。"
fi

systemctl disable --now pdg-bot pdg-probe81 pdg-web mosdns mihomo pdg-mitm pdg-rules-update.timer pdg-health.timer 2>/dev/null || true
[[ "$SB_OWNED" == 1 ]] && systemctl disable --now sing-box 2>/dev/null || true
rm -f /etc/systemd/system/{pdg-bot,pdg-probe81,pdg-web,mosdns,mihomo,pdg-mitm,pdg-rules-update,pdg-health}.service \
      /etc/systemd/system/pdg-rules-update.timer /etc/systemd/system/pdg-health.timer \
      /etc/systemd/journald.conf.d/50-pdg.conf /etc/systemd/system/journald.conf.d/50-pdg.conf   # 正确路径 + 历史错路径都删
rm -rf /opt/pdg-web
rm -rf /var/lib/privdns-gateway/web-imports
rm -f /usr/local/bin/pdg-webctl
if [[ "$QUIC_CLEAN" == 1 ]]; then
  rm -f /etc/systemd/system/pdg-quic-routing.service \
        /usr/local/libexec/pdg-quic-routing.sh
fi
[[ "$SB_OWNED" == 1 ]] && rm -f "$SB_UNIT"
systemctl daemon-reload
systemctl restart systemd-journald 2>/dev/null || true   # journald CanReload=no, 必须 restart 才会松开封顶

# 防火墙的持久文件与运行态分别做 ownership 校验。只摘除 marker/schema 均合法的 owned
# ``table inet pdg``；同名 foreign 表原样保留。绝不拿安装前整份 nftables.conf 覆盖当前文件，
# 因为安装后由管理员或其它服务加入的规则也必须保留。
_UN_NFT="" _UN_SCAN="" _UN_MERGE="" _UN_NFTTXN="" FIREWALL_WARN=""
for _l in "$_UN_HERE/lib/nftbin.sh" /opt/privdns-gateway/lib/nftbin.sh; do
  [[ -f "$_l" ]] || continue
  # shellcheck source=lib/nftbin.sh
  source "$_l" && _UN_NFT="$(pdg_nft_bin || true)"
  break
done
[[ -n "$_UN_NFT" ]] || _UN_NFT="$(command -v nft 2>/dev/null || true)"   # 判据文件缺失时的兜底
for _p in "$_UN_HERE/deploy/bot/nftscan.py" /opt/pdg-bot/nftscan.py; do
  [[ -f "$_p" ]] && { _UN_SCAN="$_p"; break; }
done
for _p in "$_UN_HERE/deploy/bot/nftmerge.py" /opt/pdg-bot/nftmerge.py; do
  [[ -f "$_p" ]] && { _UN_MERGE="$_p"; break; }
done
for _l in "$_UN_HERE/lib/nfttxn.sh" /opt/privdns-gateway/lib/nfttxn.sh; do
  [[ -f "$_l" ]] || continue
  # shellcheck source=lib/nfttxn.sh
  source "$_l" && _UN_NFTTXN="1"
  break
done

if [[ -n "$_UN_MERGE" && -f /etc/nftables.conf ]]; then
  _un_out="$(mktemp)" || _un_out=""
  _un_rc=0
  if [[ -z "$_un_out" ]]; then
    FIREWALL_WARN="${FIREWALL_WARN}无法创建持久防火墙临时文件；"
  else
    python3 "$_UN_MERGE" --remove /etc/nftables.conf "$_un_out" 2>/dev/null || _un_rc=$?
    if [[ "$_un_rc" == 0 ]]; then
      if [[ -n "$_UN_NFTTXN" && -n "$_UN_NFT" ]]; then
        pdg_nft_atomic_install "$_un_out" /etc/nftables.conf "$_UN_NFT" \
          || FIREWALL_WARN="${FIREWALL_WARN}持久防火墙未通过 nft -c 或原子写回失败，原文件已保留；"
      else
        FIREWALL_WARN="${FIREWALL_WARN}缺 nft 原子校验组件，持久配置未改；"
      fi
    elif [[ "$_un_rc" == 4 ]]; then
      FIREWALL_WARN="${FIREWALL_WARN}持久 table inet pdg 为 foreign，已保留；"
    else
      FIREWALL_WARN="${FIREWALL_WARN}无法安全摘除持久 owned 表，已保留；"
    fi
    rm -f "$_un_out"
  fi
elif [[ -z "$_UN_MERGE" ]]; then
  FIREWALL_WARN="${FIREWALL_WARN}缺少 ownership splice 工具，持久配置未改；"
fi

_un_live_rc=0
if [[ -n "$_UN_SCAN" ]]; then
  python3 "$_UN_SCAN" --table-status=live >/dev/null 2>&1 || _un_live_rc=$?
  case "$_un_live_rc" in
    0) if [[ -n "$_UN_NFT" ]]; then
         "$_UN_NFT" delete table inet pdg 2>/dev/null \
           || FIREWALL_WARN="${FIREWALL_WARN}运行态 owned 表删除失败；"
       else
         FIREWALL_WARN="${FIREWALL_WARN}找不到 nft，运行态 owned 表未删；"
       fi ;;
    1) : ;; # 不存在
    3) FIREWALL_WARN="${FIREWALL_WARN}运行态 table inet pdg 为 foreign，已保留；" ;;
    *) FIREWALL_WARN="${FIREWALL_WARN}无法确认运行态表归属，已保留；" ;;
  esac
else
  FIREWALL_WARN="${FIREWALL_WARN}缺少 ownership 扫描器，运行态表未改；"
fi
# DNS: 还原 systemd-resolved 与 resolv.conf
systemctl list-unit-files 2>/dev/null | grep -q '^systemd-resolved' && systemctl enable --now systemd-resolved 2>/dev/null || true
RESOLV_WARN=""
if [[ -e /etc/resolv.conf.pdg-orig ]]; then
  # Docker/LXC 里 /etc/resolv.conf 是 bind mount: rm/mv 都会 EBUSY, 但**内容能原地写回**。
  # 老写法直接 rm+mv, 失败了也照样往下走并宣布"已完成" —— 机器上留着指向本机 mosdns 的
  # resolv.conf, 而 mosdns 已经被卸载, 于是整机没 DNS。
  if rm -f /etc/resolv.conf 2>/dev/null && mv /etc/resolv.conf.pdg-orig /etc/resolv.conf 2>/dev/null; then
    :
  elif cat /etc/resolv.conf.pdg-orig > /etc/resolv.conf 2>/dev/null; then
    # 退化路径丢的是"原来是个符号链接"这一属性, 内容(上游 DNS)是对的
    rm -f /etc/resolv.conf.pdg-orig 2>/dev/null
  else
    RESOLV_WARN="1"                       # 备份**不删**: 留着让用户能自己恢复
  fi
elif [[ -e /run/systemd/resolve/stub-resolv.conf ]]; then
  ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null \
    || RESOLV_WARN="1"
fi

[[ -n "$FIREWALL_WARN" ]] && echo "⚠️  防火墙未完全移除: $FIREWALL_WARN"
[[ -n "$QUIC_WARN" ]] && echo "⚠️  QUIC routing 未完全移除: $QUIC_WARN"
if [[ -n "$RESOLV_WARN" ]]; then
  echo "⚠️  /etc/resolv.conf 未能还原(可能是 Docker/LXC 的 bind mount, 删不掉也写不进)。"
  echo "    现在它可能仍指向已被卸载的本机 mosdns → 整机 DNS 会不通。请手工恢复:"
  [[ -e /etc/resolv.conf.pdg-orig ]] \
    && echo "      cat /etc/resolv.conf.pdg-orig > /etc/resolv.conf   # 备份已保留" \
    || echo "      在 /etc/resolv.conf 里填一个可用的 nameserver(如 nameserver 1.1.1.1)"
  echo "已停止并移除 systemd 单元及可确认 owned 的防火墙表；DNS 未能完全还原(见上)。"
else
  echo "已停止并移除 systemd 单元及可确认 owned 的防火墙表，并尽量还原 DNS。"
fi
echo "保留: /etc/mosdns /etc/sing-box /etc/mihomo /etc/privdns-gateway/web.json /opt/pdg-bot 与 Let's Encrypt 证书。"
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
  # Web 认证配置只在显式 purge 时删除；普通卸载只移除代码/unit 并保留它。
  rm -f /etc/privdns-gateway/web.json
  rm -rf /etc/mosdns /etc/mihomo
  # Failed route cleanup must retain provenance.  Deleting a corrupt/mismatched
  # state file here would make later safe cleanup impossible.
  if [[ "$QUIC_CLEAN" == 1 ]]; then
    rm -rf /etc/privdns-gateway /opt/pdg-bot   # 含 bot.env(token) + CA 私钥
  else
    echo "[--purge] /etc/privdns-gateway 与 /opt/pdg-bot 因 QUIC ownership 未收口而保留。"
  fi
  # /etc/sing-box 是本项目的数据模型目录(config.json/rs/ui), 里面有出口密码/UUID/节点地址。
  # 按**数据模型归属**判, 不看运行时归属 —— v1.6 起本项目不装 sing-box 运行时, 拿运行时归属
  # 判的话纯 mihomo 新装机器永远删不掉它, 凭据就留在盘上了。证明不了归属仍旧一律保留。
  [[ "$MODEL_OWNED" == 1 || "$SB_OWNED" == 1 ]] && rm -rf /etc/sing-box
  rm -f /usr/local/bin/mosdns /usr/local/bin/mihomo \
        /usr/local/bin/pdg /usr/local/bin/pdg-set-token /usr/local/bin/pdg-webctl \
        /usr/local/bin/proxy-gateway-open-cert-http.sh \
        /usr/local/bin/proxy-gateway-restore-firewall.sh \
        /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
  # sing-box 二进制同样只删本项目装的; 来源不明的留给用户自己处置
  [[ "$SB_OWNED" == 1 ]] && rm -f /usr/local/bin/sing-box
  # 保留清单(unit / 二进制 / 整个 /etc/sing-box)一次性报全, 不散在各处只提一句
  if [[ "$SB_OWNED" == 0 ]] && declare -F pdg_singbox_kept_paths >/dev/null; then
    if [[ "$MODEL_OWNED" == 1 ]]; then
      _sb_report_kept                              # 模型已删, 只报 unit/二进制
    else
      _sb_report_kept with-config
      [[ -d /etc/sing-box ]] && echo "  /etc/sing-box 判不出归属的原因: $MODEL_WHY"
    fi
  fi
  if [[ "$QUIC_CLEAN" == 1 ]]; then
    rm -rf /opt/privdns-gateway /var/lib/privdns-gateway
  else
    # Repository fallback carries lib helpers and the coherent parser source.
    # Keep it together with state/profile so manual recovery remains runnable.
    echo "[--purge] /opt/privdns-gateway 与快照因 QUIC recovery 需要而保留。"
  fi
  echo "已 purge。证书目录 /etc/letsencrypt 仍保留(含账户), 如需彻底清除请手动 certbot delete。"
fi
