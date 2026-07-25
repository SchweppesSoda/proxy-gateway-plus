#!/usr/bin/env bash
# nft 可执行文件的定位 —— pdg / uninstall / certbot 钩子共用的**同一份**判据。
#
# 为什么不能只 `command -v nft`: nft 装在 /usr/sbin。`su`(不带 -)、cron、systemd 单元的
# 默认 PATH、精简容器里 root 的 PATH 都可能没有 sbin —— 那时 `command -v nft` 查不到, 而
# 机器上明明有一整套 nftables 规则正在生效。被当成"没装 nft"的后果各不相同, 但都难查:
#   · pdg platform: 切换后的 nftables.conf 根本没校验就放行(下次开机防火墙起不来);
#   · uninstall:    磁盘配置还原了, 内核里的 inet pdg 表还在(端口继续被 policy drop 挡着);
#   · certbot 钩子: 80 口没放行就去做 ACME HTTP-01, 证书续不上。
#
# 候选路径的**唯一事实源**是 deploy/bot/nftscan.py 的 NFT_CANDIDATES: 优先直接问它
# (`--nft-path`, 同时覆盖 PATH 与候选目录); 机器上没有 python3 时, 退而从**同一份文件**里
# 把那几个路径读出来 —— 仍是同一份清单, 不在 shell 里另写一套会漂移的。
# 连 nftscan.py 都找不到(判据脚本缺失)才只能回到 PATH。
#
# 找到 → 打印绝对路径并返回 0; 找不到 → 不打印, 返回 1。

pdg_nft_bin(){
  local repo="${REPO_DIR:-/opt/privdns-gateway}" scan="" m out cand
  for m in "$repo/deploy/bot/nftscan.py" /opt/pdg-bot/nftscan.py; do
    [[ -f "$m" ]] && { scan="$m"; break; }
  done
  if [[ -n "$scan" ]] && command -v python3 >/dev/null 2>&1; then
    out="$(python3 "$scan" --nft-path 2>/dev/null || true)"
    [[ -n "$out" && -x "$out" ]] && { printf '%s\n' "$out"; return 0; }
  fi
  out="$(command -v nft 2>/dev/null || true)"
  [[ -n "$out" && -x "$out" ]] && { printf '%s\n' "$out"; return 0; }
  [[ -n "$scan" ]] || return 1
  # 没有 python3(或它跑不起来): 从 nftscan.py 里读同一份候选清单, 自己逐个试
  while read -r cand; do
    [[ -n "$cand" && -x "$cand" ]] && { printf '%s\n' "$cand"; return 0; }
  done < <(sed -n '/^NFT_CANDIDATES = (/,/)/p' "$scan" | grep -oE '"/[^"]+"' | tr -d '"')
  return 1
}
