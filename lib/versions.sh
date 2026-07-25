#!/usr/bin/env bash
# shellcheck disable=SC2034  # 本文件供 source, 变量在 install.sh / tests 里用
# ─────────────────────────────────────────────────────────────────────────────
# 单一可信源: 二进制版本 + 钉死 SHA256(供应链校验)。install.sh 与 tests/ 共用。
#
# 升级版本步骤:
#   1) 改下面的 *_VER;
#   2) 下载官方 release 重算: sha256sum mosdns-linux-<arch>.zip / mihomo-linux-<arch>-<ver>.gz
#   3) 把哈希同步到 PDG_SHA256(amd64 + arm64)。
# 哈希取自上游官方 GitHub Release(信任锚 = 官方发布页),装机/测试时逐字节比对,不符即拒装。
# ─────────────────────────────────────────────────────────────────────────────
MOSDNS_VER="v5.3.4"
MIHOMO_VER="v1.19.29"         # 流量内核: mihomo/clash.meta, sniffer.override-destination 无版本天花板, 活跃维护可更新
ZASHBOARD_VER="v3.15.0"       # 观测面板(纯静态前端, 由 external_ui 托管; dist-no-fonts 最小、不依赖 CDN; mihomo 原生 clash 核也可托管)

# key = <name>-<arch>(arch: amd64 / arm64); zashboard 为纯前端, 与架构无关(单一哈希)
declare -A PDG_SHA256=(
  [mosdns-amd64]="3abcc73080789eb1ccca78dab5049b85ac1e9b8f865ab60158a527b77cd72e85"
  [mosdns-arm64]="82d80a1a21606fca0bc6b65ac6f90d30cff6bb4a19a6ab6a246cf247dbb78bc0"
  # mihomo(流量内核): 官方 release 的 mihomo-linux-<arch>-<ver>.gz
  [mihomo-amd64]="60de76a35a6cbf7b4fa4a20f5c257c24345d1d635ab1aa3877022a1997ef413c"
  [mihomo-arm64]="9a868b5e4e0ad91d9d71e1b41b0cfce78aaba44360c30df74a723f8e3926a86c"
  [zashboard]="403b351d3663f5fe65db053cb2f3dc980108d8f86e8c6968d56164d3452592e1"
)

# ── 内核版本判定: 必须精确匹配, 不能用子串 ──────────────────────────────────
# `mihomo -v | grep -q "$MIHOMO_VER"` 是子串判断: 期望 v1.19.1 时, 机器上跑 v1.19.10 也会被
# 判成"已是钉死版本" → 装机/更新都跳过下载, 内核实际没升上去。这类错判只在版本号进位到两位
# 数时才出现, 极难发现。故统一解析出完整版本字段后做等值比较。

# 从 `mihomo -v` 输出解析版本(如 v1.19.29); 解析不出则输出空。
pdg_mihomo_version(){
  local out
  out="$(mihomo -v 2>/dev/null | head -1)" || return 0
  [[ "$out" =~ v?([0-9]+\.[0-9]+\.[0-9]+) ]] && printf 'v%s\n' "${BASH_REMATCH[1]}"
}

# 当前 mihomo 是否**恰好**是 $1 指定的版本(带不带 v 前缀都行)。
# 读不到版本(没装/输出异常)一律返回非 0 —— 宁可多装一次, 也不能跳过该做的安装。
pdg_mihomo_is_version(){
  local want="${1#v}" got
  got="$(pdg_mihomo_version)"; got="${got#v}"
  [[ -n "$got" && "$got" == "$want" ]]
}

# mosdns 同理。装机曾用 `command -v mosdns` 判定 —— PATH 上有任何一个 mosdns(第三方装的、
# 或早年遗留的老版)就跳过下载, 于是既不升到钉死版, 也**跳过了 SHA256 供应链校验**,
# 网关最终跑着一个来路不明的解析器, 而安装日志上连"下载 mosdns"这行都不会出现。
pdg_mosdns_version(){
  local out
  out="$(mosdns version 2>/dev/null | head -1)" || return 0
  [[ "$out" =~ ([0-9]+\.[0-9]+\.[0-9]+) ]] && printf 'v%s\n' "${BASH_REMATCH[1]}"
}

pdg_mosdns_is_version(){
  local want="${1#v}" got
  got="$(pdg_mosdns_version)"; got="${got#v}"
  [[ -n "$got" && "$got" == "$want" ]]
}

# pdg_verify_sha256 <文件> <期望hash> [名称]  → 不符返回非 0 并打印期望/实际
pdg_verify_sha256(){
  local file="$1" exp="$2" name="${3:-$1}" got
  if [[ -z "$exp" ]]; then
    echo "[x] 缺少 $name 的钉死 SHA256(lib/versions.sh 未覆盖该版本/架构)" >&2
    return 1
  fi
  got=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
  if [[ "$got" != "$exp" ]]; then
    echo "[x] SHA256 校验失败: $name" >&2
    echo "    期望 $exp" >&2
    echo "    实际 ${got:-<空: 文件不存在或读不出>}" >&2
    return 1
  fi
  return 0
}
