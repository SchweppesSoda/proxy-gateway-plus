#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 每个 E2E 都必须**自带完整前提**(hermetic): 在同一个环境里按任意顺序连着跑, 结果要和各自
# 单独跑一模一样。
#
# 这条纪律被破过一次, 而且是在 CI 上: e2e-cross-version-rollback 会在 /usr/local/bin 留下
# 一个 sing-box 二进制, 而 e2e-install 的 reset_box 不清它 —— 下一个脚本的装机路径于是判成
# "机器上已有来源不明的 sing-box"直接中止。CI 里 e2e 是同一个 Debian 容器里顺序跑的, 所以
# 单独跑 23/23 的用例在 CI 上只有 11/34, 而失败原因跟被测代码毫无关系。
#
# 本用例把 CI 的串行条件原样搭出来: 一个沙箱(= 一个容器)里, 用 PDG_E2E_ISOLATED=1 依次跑
# 多个脚本, 断言每个都全绿。CI 侧另外改成了 matrix(每个脚本独立 job/独立容器), 两道保险。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
E2E_ROOT="${E2E_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 串行跑哪些脚本: 默认取"曾经互相踩过"的那一组(跨版本回滚留 sing-box → 装机 → 更新)。
SCRIPTS="${PDG_SERIAL_SCRIPTS:-e2e-cross-version-rollback.sh e2e-install.sh e2e-update.sh}"

pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

# ── 外层: 造一个沙箱(等价于 CI 的一次性容器), 内层在里面串行跑 ────────────────
if [[ "${PDG_SERIAL_INNER:-}" != 1 ]]; then
  if [[ "${PDG_E2E_ISOLATED:-}" == 1 && "$(id -u)" == 0 ]]; then
    PDG_SERIAL_INNER=1 exec bash "$0" "$@"       # CI: 本来就在一次性容器里
  fi
  unshare -rm true 2>/dev/null || { echo "[SKIP] 本环境不支持 unshare -rm"; exit 0; }
  OVL="$(mktemp -d)"
  mkdir -p "$OVL"/{eu,ew,bu,bw,ou,ow,vu,vw}
  mkdir -p "$OVL"/eu/{mosdns/rules,sing-box,mihomo,privdns-gateway,systemd/system,systemd/journald.conf.d}
  : > "$OVL"/eu/nftables.conf
  rc=0
  PDG_SERIAL_INNER=1 OVL="$OVL" E2E_ROOT="$E2E_ROOT" unshare -rm bash "$0" "$@" || rc=$?
  unshare -rm bash -c 'rm -rf "$1"' _ "$OVL" 2>/dev/null || rm -rf "$OVL" 2>/dev/null
  exit "$rc"
fi

# ── 内层: 挂上和单脚本沙箱同样的 overlay, 然后串行跑 ─────────────────────────
if [[ -n "${OVL:-}" ]]; then
  mount -t overlay overlay -o "lowerdir=/etc,upperdir=$OVL/eu,workdir=$OVL/ew" /etc \
    || { echo "[SKIP] overlay /etc 挂不上"; exit 0; }
  mount -t overlay overlay -o "lowerdir=/usr/local/bin,upperdir=$OVL/bu,workdir=$OVL/bw" /usr/local/bin
  mount -t overlay overlay -o "lowerdir=/opt,upperdir=$OVL/ou,workdir=$OVL/ow" /opt
  mount -t tmpfs tmpfs /run 2>/dev/null || true
  mount -t overlay overlay -o "lowerdir=/var/lib,upperdir=$OVL/vu,workdir=$OVL/vw" /var/lib \
    2>/dev/null || mount -t tmpfs tmpfs /var/lib 2>/dev/null || true
  mkdir -p /var/lib/privdns-gateway 2>/dev/null || true
  grep -q 'directory = \*' /etc/gitconfig 2>/dev/null \
    || printf '[safe]\n\tdirectory = *\n' >> /etc/gitconfig 2>/dev/null || true
fi

echo "串行顺序: $SCRIPTS"
echo "(每个脚本都以 PDG_E2E_ISOLATED=1 跑在同一个沙箱里 —— 与 CI 的容器 job 同条件)"
for s in $SCRIPTS; do
  [[ -f "$HERE/$s" ]] || { bad "找不到 $s"; continue; }
  out="$(PDG_E2E_ISOLATED=1 E2E_ROOT="$E2E_ROOT" bash "$HERE/$s" 2>&1)"; rc=$?
  line="$(grep -oE '通过 [0-9]+, 失败 [0-9]+' <<<"$out" | tail -1)"
  npass="$(grep -oE '通过 [0-9]+' <<<"$line" | grep -oE '[0-9]+')"
  if [[ "$rc" != 0 ]] || grep -q '失败 [1-9]' <<<"${line:-失败 0}"; then
    bad "$s 串行跑失败 rc=$rc  ($line)"
    grep -E '^\[FAIL\]' <<<"$out" | head -5 | sed 's/^/       /'
  elif [[ -z "$npass" || "$npass" == 0 ]]; then
    # 断言数为 0 = 这个脚本被 skip 了。串行场景下最常见的原因正是"上一个脚本留下/清掉了
    # 什么, 让这个脚本的前提不成立" —— 当成绿的就是假绿, 必须点出来。
    bad "$s 串行跑时被跳过(零断言) —— 前提在串行环境里不成立:"
    grep -E '^\[SKIP\]|SKIP' <<<"$out" | head -3 | sed 's/^/       /'
  else
    ok "$s 串行跑仍全绿  ($line)"
  fi
done

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
