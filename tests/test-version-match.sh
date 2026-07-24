#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 内核版本判定必须**精确匹配**, 不能用子串。
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

mkbin(){   # $1=假 mihomo 报告的版本串
  mkdir -p "$WORK/bin"
  printf '#!/bin/sh\ncase "$1" in -v|version) echo "Mihomo Meta %s linux amd64 with go1.26.5";; esac\nexit 0\n' \
    "$1" > "$WORK/bin/mihomo"
  chmod 755 "$WORK/bin/mihomo"
  export PATH="$WORK/bin:$ROOT/tests/.nonexistent:$PATH"
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
export PATH="$WORK/empty:$PATH"; mkdir -p "$WORK/empty"
rm -f "$WORK/bin/mihomo"
pdg_mihomo_is_version v1.19.29 \
  && bad "内核不存在却判成已是目标版本(会跳过安装)" || ok "读不到版本 → 判为非目标版本(不会跳过安装)"

# ── 7. 三个调用点都不再用子串判断 ──
if grep -nE 'mihomo -v [^|]*\| *grep -q' "$ROOT/install.sh" "$ROOT/deploy/bot/pdg.sh" >/dev/null 2>&1; then
  bad "仍有 mihomo 版本子串判断: $(grep -nE 'mihomo -v [^|]*\| *grep -q' "$ROOT/install.sh" "$ROOT/deploy/bot/pdg.sh" | head -2)"
else
  ok "install.sh / pdg.sh 已无 mihomo 版本子串判断"
fi

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
