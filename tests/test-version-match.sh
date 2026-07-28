#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 二进制版本判定必须**精确匹配**, 不能用子串, 也不能只看"装没装"。
#
# 旧写法 `mihomo -v | grep -q "$MIHOMO_VER"` 是子串判断: 期望 v1.19.1 时, 机器上跑着
# v1.19.10 也会被判成"已是钉死版本" → 该升的不升(装机/更新都会跳过下载), 而且这类错判
# 只在版本号进位到两位数时才出现, 极难发现。反向同理。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

# shellcheck source=lib/versions.sh
source "$ROOT/lib/versions.sh"
# shellcheck source=lib/mosdns-artifact.sh
source "$ROOT/lib/mosdns-artifact.sh"

mkbin(){   # $1=假 mihomo 报告的版本串
  mkdir -p "$WORK/bin"
  printf '#!/bin/sh\ncase "$1" in -v|version) echo "Mihomo Meta %s linux amd64 with go1.26.5";; esac\nexit 0\n' \
    "$1" > "$WORK/bin/mihomo"
  chmod 755 "$WORK/bin/mihomo"
  export PATH="$WORK/bin:$ROOT/tests/.nonexistent:$PATH"
}

mkmosdns(){   # $1=假 mosdns 报告的版本串
  mkdir -p "$WORK/bin"
  printf '#!/bin/sh\ncase "$1" in version|-v) echo "%s";; esac\nexit 0\n' "$1" > "$WORK/bin/mosdns"
  chmod 755 "$WORK/bin/mosdns"
  export PATH="$WORK/bin:$PATH"
}

# ── 1. 精确相等 → 真 ──
mkbin v1.19.29
pdg_mihomo_is_version v1.19.29 && ok "版本相同 → 判定为已是目标版本" || bad "相同版本判成不同"
pdg_mihomo_is_version 1.19.29  && ok "期望值不带 v 前缀也能正确比较" || bad "无 v 前缀比较失败"

# ── 2. 前缀式误判(核心回归): 机器 v1.19.10, 期望 v1.19.1 → 必须为假 ──
mkbin v1.19.10
pdg_mihomo_is_version v1.19.1 \
  && bad "v1.19.1 匹配上了 v1.19.10(子串误判, 该升的不会升)" \
  || ok "v1.19.1 不匹配 v1.19.10(不再子串误判)"
pdg_mihomo_is_version v1.19.10 && ok "v1.19.10 与自身精确匹配" || bad "v1.19.10 与自身不匹配"

# ── 3. 反向: 机器 v1.19.1, 期望 v1.19.10 → 假 ──
mkbin v1.19.1
pdg_mihomo_is_version v1.19.10 \
  && bad "机器 v1.19.1 被当成 v1.19.10" || ok "机器 v1.19.1 不会被当成 v1.19.10"

# ── 4. 其它易混形态 ──
mkbin v1.2.3
pdg_mihomo_is_version v1.2.30 && bad "v1.2.30 匹配了 v1.2.3" || ok "v1.2.3 不匹配 v1.2.30"
pdg_mihomo_is_version v11.2.3 && bad "v11.2.3 匹配了 v1.2.3" || ok "v1.2.3 不匹配 v11.2.3"

# ── 5. 解析函数本身 ──
mkbin v1.19.29
[[ "$(pdg_mihomo_version)" == "v1.19.29" ]] \
  && ok "从 mihomo -v 输出里解析出完整版本字段" || bad "解析结果=$(pdg_mihomo_version)"

# ── 6. 拿不到版本(二进制不存在/输出异常)→ 必须判"不是目标版本", 好让调用方去装 ──
# 用**不含内核二进制的 PATH** 跑子 shell: 开发机上可能真装着 mihomo/mosdns(它们在
# /usr/local/bin), 只删自己的桩挡不住它顶上来。保留 /usr/bin:/bin 好让 head 等仍可用。
mkdir -p "$WORK/empty"
NOBIN="$WORK/empty:/usr/bin:/bin"
# shellcheck disable=SC2123  # 有意在子 shell 里改 PATH, 只影响这一次调用
( PATH="$NOBIN"; pdg_mihomo_is_version v1.19.29 ) \
  && bad "内核不存在却判成已是目标版本(会跳过安装)" || ok "读不到版本 → 判为非目标版本(不会跳过安装)"

# ── 7. 三个调用点都不再用子串判断 ──
if grep -nE 'mihomo -v [^|]*\| *grep -q' "$ROOT/install.sh" "$ROOT/deploy/bot/pdg.sh" >/dev/null 2>&1; then
  bad "仍有 mihomo 版本子串判断: $(grep -nE 'mihomo -v [^|]*\| *grep -q' "$ROOT/install.sh" "$ROOT/deploy/bot/pdg.sh" | head -2)"
else
  ok "install.sh / pdg.sh 已无 mihomo 版本子串判断"
fi

# ── 8. mosdns 的语义版本解析仍须精确；生产判定还必须区分 flavor ──
# 旧 install.sh 是 `command -v mosdns` —— PATH 上有任何一个 mosdns(第三方/老版)就跳过下载,
# 于是既不升到钉死版, 也**跳过了 SHA256 供应链校验**, 网关跑着来路不明的解析器。
mkmosdns v5.3.4
pdg_mosdns_is_version v5.3.4  && ok "mosdns: 版本相同 → 判定为已是目标版本" || bad "mosdns 相同版本判成不同"
pdg_mosdns_binary_is_target "$WORK/bin/mosdns" \
  && bad "mosdns: stock v5.3.4 被当成 no-ticket flavor" \
  || ok "mosdns: stock v5.3.4 与 no-ticket flavor 明确区分"
mkmosdns "$MOSDNS_BUILD_VERSION"
pdg_mosdns_binary_is_target "$WORK/bin/mosdns" \
  && ok "mosdns: 精确 build marker → 判定为目标 flavor" \
  || bad "mosdns: no-ticket build marker 未被识别"
mkmosdns v5.3.4
pdg_mosdns_is_version v5.3.40 && bad "mosdns: v5.3.40 匹配了 v5.3.4" || ok "mosdns: v5.3.4 不匹配 v5.3.40"
mkmosdns v5.3.1
pdg_mosdns_is_version v5.3.4 && bad "mosdns: 老版 v5.3.1 被当成 v5.3.4(会跳过升级)" \
  || ok "mosdns: 老版本 → 判为非目标版本(会去装钉死版)"
# shellcheck disable=SC2123  # 同上
( PATH="$NOBIN"; pdg_mosdns_is_version v5.3.4 ) \
  && bad "mosdns 不存在却判成已是目标版本" || ok "mosdns 未安装 → 判为非目标版本"

# ── 9. install.sh 必须用 flavor/provenance，不得只看存在或语义版本 ──
if grep -qE '^\s*if ! (command -v mosdns|pdg_mosdns_is_version)' "$ROOT/install.sh"; then
  bad "install.sh 仍只按存在/语义版本判定(stock v5.3.4 会跳过修补)"
elif grep -q 'pdg_mosdns_is_project_build' "$ROOT/install.sh"; then
  ok "install.sh 的 mosdns 判定要求精确 flavor/provenance"
else
  bad "install.sh 未调用 MosDNS 精确 flavor/provenance 判据"
fi

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
