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

# The outer namespace hashes the complete host /usr/local tree before and after
# the inner overlay run.  Contents, names, modes and symlink targets all feed
# the deterministic tar stream, so a missed overlay such as libexec is visible.
pdg_usr_local_sentinel(){
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    -cf - -C /usr/local . | sha256sum | awk '{print $1}'
}

pdg_serial_overlay_valid(){
  local root="${PDG_SERIAL_TMP_ROOT:-}" overlay="${OVL:-}" resolved resolved_root
  [[ -n "$root" && -n "$overlay" && -d "$root" && -d "$overlay" \
     && ! -L "$overlay" ]] || return 1
  resolved_root="$(cd "$root" 2>/dev/null && pwd -P)" || return 1
  [[ "$resolved_root" == "$root" ]] || return 1
  case "$overlay" in
    "$root"/pdg-e2e-serial.*) ;;
    *) return 1 ;;
  esac
  resolved="$(cd "$overlay" 2>/dev/null && pwd -P)" || return 1
  [[ "$resolved" == "$overlay" ]]
}

pdg_serial_cleanup(){
  pdg_serial_overlay_valid || {
    echo "[FAIL] 拒绝清理不可信的 serial overlay 路径" >&2
    return 1
  }
  local target="$OVL" root="$PDG_SERIAL_TMP_ROOT"
  if unshare -rm bash -c '
      set -u
      target=$1; root=$2
      case "$target" in "$root"/pdg-e2e-serial.*) ;; *) exit 64;; esac
      [[ -n "$target" && -d "$target" && ! -L "$target" ]] || exit 65
      rm -rf -- "$target"
    ' _ "$target" "$root" 2>/dev/null; then
    [[ ! -e "$target" ]] && return 0
  fi
  pdg_serial_overlay_valid || return 1
  rm -rf -- "$OVL"
}

# Resolve the trusted temporary root, create one serial overlay directory and
# validate the exact path before callers may populate or mount it.  The normal
# E2E path and the fault-injection probe deliberately share this boundary.
pdg_serial_create_overlay_root(){
  PDG_SERIAL_TMP_ROOT="$(cd "${TMPDIR:-/tmp}" 2>/dev/null && pwd -P)" \
    || { echo "[FAIL] 无法解析 serial E2E 临时根" >&2; return 1; }
  [[ -n "$PDG_SERIAL_TMP_ROOT" && -d "$PDG_SERIAL_TMP_ROOT" ]] \
    || { echo "[FAIL] serial E2E 临时根不可信" >&2; return 1; }
  OVL="$(mktemp -d "$PDG_SERIAL_TMP_ROOT/pdg-e2e-serial.XXXXXX")" \
    || { echo "[FAIL] 无法建立 serial E2E overlay 临时目录" >&2; return 1; }
  pdg_serial_overlay_valid \
    || { echo "[FAIL] serial E2E overlay 临时目录验证失败" >&2; return 1; }
}

# Internal test contract: exercise only the trusted-TMP/mktemp/path-validation
# boundary.  It can never enter a namespace or run an E2E body, and it always
# exits non-zero.  An unexpected successful mktemp is validated and removed
# before returning failure.  Exact argv dispatch below prevents this probe from
# weakening the normal full-/usr/local sentinel path.
pdg_serial_test_overlay_mktemp_failure(){
  if pdg_serial_create_overlay_root; then
    pdg_serial_cleanup \
      || { echo "[FAIL] test-only serial overlay cleanup failed" >&2; return 1; }
    echo "[FAIL] test-only serial mktemp unexpectedly succeeded" >&2
    return 97
  fi
  return 96
}

if [[ "$#" -ne 0 ]]; then
  if [[ "$#" -eq 1 && "$1" == "__test-only-overlay-mktemp-failure" ]]; then
    pdg_serial_test_overlay_mktemp_failure
    exit $?
  fi
  echo "[FAIL] unsupported e2e-serial-hermetic argument" >&2
  exit 64
fi

# ── 外层: 造一个沙箱(等价于 CI 的一次性容器), 内层在里面串行跑 ────────────────
if [[ "${PDG_SERIAL_INNER:-}" != 1 ]]; then
  if [[ "${PDG_E2E_ISOLATED:-}" == 1 && "$(id -u)" == 0 ]]; then
    PDG_SERIAL_INNER=1 exec bash "$0" "$@"       # CI: 本来就在一次性容器里
  fi
  unshare -rm true 2>/dev/null || { echo "[SKIP] 本环境不支持 unshare -rm"; exit 0; }
  HOST_USR_LOCAL_BEFORE="$(pdg_usr_local_sentinel)" \
    || { echo "[FAIL] 无法建立宿主 /usr/local sentinel"; exit 1; }
  [[ -n "$HOST_USR_LOCAL_BEFORE" ]] \
    || { echo "[FAIL] 宿主 /usr/local sentinel 为空"; exit 1; }
  pdg_serial_create_overlay_root || exit 1
  mkdir -p "$OVL"/{eu,ew,bu,bw,ou,ow,vu,vw} \
    || { echo "[FAIL] 无法建立 serial E2E overlay 层" >&2; pdg_serial_cleanup; exit 1; }
  mkdir -p "$OVL"/eu/{mosdns/rules,sing-box,mihomo,privdns-gateway,systemd/system,systemd/journald.conf.d} \
    || { echo "[FAIL] 无法预置 serial E2E /etc upperdir" >&2; pdg_serial_cleanup; exit 1; }
  : > "$OVL"/eu/nftables.conf \
    || { echo "[FAIL] 无法预置 serial 隔离 nftables 配置" >&2; pdg_serial_cleanup; exit 1; }
  rc=0
  PDG_SERIAL_INNER=1 OVL="$OVL" PDG_SERIAL_TMP_ROOT="$PDG_SERIAL_TMP_ROOT" \
    E2E_ROOT="$E2E_ROOT" unshare -rm bash "$0" "$@" || rc=$?
  pdg_serial_cleanup || rc=1
  HOST_USR_LOCAL_AFTER="$(pdg_usr_local_sentinel)" || {
    echo "[FAIL] 无法复核宿主 /usr/local sentinel"
    rc=1
  }
  if [[ -z "${HOST_USR_LOCAL_AFTER:-}" \
        || "$HOST_USR_LOCAL_AFTER" != "$HOST_USR_LOCAL_BEFORE" ]]; then
    echo "[FAIL] 串行 namespace 改变了宿主 /usr/local"
    rc=1
  else
    echo "[OK]   namespace 外 sentinel 确认宿主 /usr/local 未变化"
  fi
  exit "$rc"
fi

# ── 内层: 挂上和单脚本沙箱同样的 overlay, 然后串行跑 ─────────────────────────
if [[ -n "${OVL:-}" ]]; then
  pdg_serial_overlay_valid \
    || { echo "[FAIL] serial E2E overlay 临时根不可信" >&2; exit 1; }
  mount -t overlay overlay -o "lowerdir=/etc,upperdir=$OVL/eu,workdir=$OVL/ew" /etc \
    || { echo "[FAIL] serial overlay /etc 挂载失败" >&2; exit 1; }
  # 覆盖整棵 /usr/local：seed_install 不只写 bin，还会安装/清理 libexec。
  # 只覆盖 bin 会让本地 userns 串行测试把 helper 写到真实宿主 /usr/local/libexec。
  mount -t overlay overlay -o "lowerdir=/usr/local,upperdir=$OVL/bu,workdir=$OVL/bw" /usr/local \
    || { echo "[FAIL] serial overlay /usr/local 挂载失败" >&2; exit 1; }
  mount -t overlay overlay -o "lowerdir=/opt,upperdir=$OVL/ou,workdir=$OVL/ow" /opt \
    || { echo "[FAIL] serial overlay /opt 挂载失败" >&2; exit 1; }
  mount -t tmpfs tmpfs /run \
    || { echo "[FAIL] serial tmpfs /run 挂载失败" >&2; exit 1; }
  mount -t overlay overlay -o "lowerdir=/var/lib,upperdir=$OVL/vu,workdir=$OVL/vw" /var/lib \
    || { echo "[FAIL] serial overlay /var/lib 挂载失败" >&2; exit 1; }
  mkdir -p /var/lib/privdns-gateway \
    || { echo "[FAIL] serial 无法建立隔离状态目录" >&2; exit 1; }
  grep -q 'directory = \*' /etc/gitconfig 2>/dev/null \
    || printf '[safe]\n\tdirectory = *\n' >> /etc/gitconfig \
    || { echo "[FAIL] serial 无法写入隔离 gitconfig" >&2; exit 1; }
elif [[ "${PDG_E2E_ISOLATED:-}" != 1 || "$(id -u)" != 0 ]]; then
  echo "[FAIL] serial inner 缺少已验证 overlay" >&2
  exit 1
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
