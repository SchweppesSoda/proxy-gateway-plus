#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 内网卡来源段(CIDR)的取值单一事实源: 校验 + 「抓包与手输并行, 谁先出结果用谁」。
# install.sh(装机)与 pdg detect-cidr(装完重识别)共用, 免两处各写一套。
#
# 为什么要并行: 抓包最长 90 秒, 而多数人其实**早就知道**自己的内网卡段。旧实现只能干等
# 满 90 秒、抓不到再手填 —— 白等一次; 更糟的是等完之后一个空回车就 die + 回滚整场安装。
# 现在开抓的同时就接受手输: 手输先到就掐掉抓包直接用, 抓包先到就用抓到的, 都不用等对方。
# ─────────────────────────────────────────────────────────────────────────────

# CIDR 形态校验: a.b.c.d/nn, 每段 0-255, 前缀 0-32。填错(如漏了 /16)会渲染出一份
# 谁都匹配不上的防火墙/mosdns 配置 —— 装完才发现分流全不生效, 故在入口就拦。
pdg_cidr_valid(){
  local s="${1:-}" ip pfx o
  [[ "$s" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]] || return 1
  ip="${s%/*}"; pfx="${s#*/}"
  (( 10#$pfx <= 32 )) || return 1
  local -a oct; IFS=. read -ra oct <<<"$ip"
  for o in "${oct[@]}"; do (( 10#$o <= 255 )) || return 1; done
  return 0
}

# 抓包识别 + 手输并行, 谁先出结果用谁。
#   $1 抓包秒数(默认 90)  $2 本机公网IP(仅用于提示文案)
#   stdout: 选定的 CIDR(未取到则空); 返回 0=取到 / 1=没取到
# 无可用终端(非交互/管道)时退化成纯抓包, 行为与旧版一致。
pdg_detect_cidr_race(){
  local dur="${1:-90}" sip="${2:-本机公网IP}"
  local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local script="$here/detect-internal-range.sh" tmp typed="" det="" pid
  tmp="$(mktemp)" || return 1

  # 没有可用终端 → 无从手输, 纯抓包(非交互装机/CI 走这条)
  if ! { true < /dev/tty; } 2>/dev/null; then
    det="$(bash "$script" "$dur" "$sip" || true)"
    rm -f "$tmp"
    [[ -n "$det" ]] && { printf '%s\n' "$det"; return 0; }
    return 1
  fi

  # 让 banner 里出现"现在就能直接输入"那句(只有支持并行手输时才提示, 免得文案说谎)
  PDG_DETECT_TYPEAHEAD=1 bash "$script" "$dur" "$sip" > "$tmp" 2>/dev/tty &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    # -t 1: 每秒回来看一眼抓包结束没有, 从而两条路谁先到都能立刻响应
    if IFS= read -r -t 1 typed < /dev/tty; then
      typed="${typed//[[:space:]]/}"
      if [[ -n "$typed" ]]; then
        kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
        rm -f "$tmp"; printf '%s\n' "$typed"; return 0
      fi
    fi
  done
  wait "$pid" 2>/dev/null
  # 抓包先到: 把用户可能敲了一半的残留清掉, 免得漏进下一个提问(平台/token)当答案
  while IFS= read -r -t 0.05 -n 4096 _ < /dev/tty; do :; done 2>/dev/null
  det="$(cat "$tmp" 2>/dev/null)"; rm -f "$tmp"
  [[ -n "$det" ]] && { printf '%s\n' "$det"; return 0; }
  return 1
}
