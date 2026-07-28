#!/usr/bin/env bash
# MosDNS hot-swap transaction: binary + provenance must succeed or roll back together.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }
xt(){ sed -n "/^$1(){/,/^}/p" "$ROOT/deploy/bot/pdg.sh"; }

eval "$(xt _core_kernel_stable)"
eval "$(xt _pdg_sha)"
eval "$(xt _core_stash_kernel)"
eval "$(xt _mosdns_restore_prev)"
eval "$(xt _mosdns_swap_verify)"

c_g(){ echo "$*"; }
c_y(){ echo "$*"; }
sleep(){ :; }
mkdir -p "$WORK/bin" "$WORK/etc"
export PDG_MOSDNS_BIN="$WORK/bin/mosdns"
export PDG_MOSDNS_ATTESTATION="$WORK/etc/mosdns-build.env"
export MOSDNS_BUILD_VERSION="v5.3.4-pdg-notickets.1"

systemctl(){
  case "${1:-}" in
    show) echo 0;;
    is-active)
      if grep -q NEW-MOSDNS "$PDG_MOSDNS_BIN" 2>/dev/null; then
        echo "${NEW_ACTIVE:-active}"
      else
        echo active
      fi;;
    restart) return "${RESTART_RC:-0}";;
    stop) return 0;;
  esac
  return 0
}
pdg_write_mosdns_attestation(){
  [[ -n "${WRITE_FAIL:-}" ]] && return 1
  printf 'NEW-ATTEST\n' >"$1"
}
pdg_mosdns_is_project_build(){ [[ -z "${VERIFY_FAIL:-}" ]]; }

cat >"$WORK/new" <<'EOF'
#!/bin/sh
# NEW-MOSDNS
exit 0
EOF
chmod 755 "$WORK/new"
NEWSHA="$(sha256sum "$WORK/new" | awk '{print $1}')"

setup_old(){
  printf '#!/bin/sh\n# OLD-MOSDNS\nexit 0\n' >"$PDG_MOSDNS_BIN"
  chmod 755 "$PDG_MOSDNS_BIN"
  printf 'OLD-ATTEST\n' >"$PDG_MOSDNS_ATTESTATION"
  OLDSHA="$(sha256sum "$PDG_MOSDNS_BIN" | awk '{print $1}')"
  OLDATSHA="$(sha256sum "$PDG_MOSDNS_ATTESTATION" | awk '{print $1}')"
  unset WRITE_FAIL VERIFY_FAIL RESTART_RC
  NEW_ACTIVE=active
}

setup_old; WRITE_FAIL=1
rc=0
_mosdns_swap_verify "$WORK/new" amd64 "$NEWSHA" "$NEWSHA" local >/dev/null 2>&1 || rc=$?
[[ "$rc" != 0 \
   && "$(sha256sum "$PDG_MOSDNS_BIN" | awk '{print $1}')" == "$OLDSHA" \
   && "$(sha256sum "$PDG_MOSDNS_ATTESTATION" | awk '{print $1}')" == "$OLDATSHA" ]] \
  && ok "证明写入失败 → 旧 binary + 旧证明逐字节恢复" \
  || bad "证明失败后未完整恢复"

setup_old; NEW_ACTIVE=failed
rc=0
_mosdns_swap_verify "$WORK/new" amd64 "$NEWSHA" "$NEWSHA" local >/dev/null 2>&1 || rc=$?
[[ "$rc" != 0 \
   && "$(sha256sum "$PDG_MOSDNS_BIN" | awk '{print $1}')" == "$OLDSHA" \
   && "$(sha256sum "$PDG_MOSDNS_ATTESTATION" | awk '{print $1}')" == "$OLDATSHA" ]] \
  && ok "新 MosDNS 不稳定 → 旧 binary + 旧证明恢复并重启" \
  || bad "不稳定后未完整恢复"

setup_old
rc=0
_mosdns_swap_verify "$WORK/new" amd64 "$NEWSHA" "$NEWSHA" local >/dev/null 2>&1 || rc=$?
left="$(find "$WORK" -type f \( -name '*.pdg-prev.*' -o -name '.mosdns-build.pdg-prev.*' \))"
[[ "$rc" == 0 \
   && "$(sha256sum "$PDG_MOSDNS_BIN" | awk '{print $1}')" == "$NEWSHA" \
   && "$(cat "$PDG_MOSDNS_ATTESTATION")" == NEW-ATTEST \
   && -z "$left" ]] \
  && ok "全部通过 → 新 binary/证明提交，事务备份清理" \
  || bad "成功路径未正确提交/清理"

rm -f "$PDG_MOSDNS_BIN" "$PDG_MOSDNS_ATTESTATION"
WRITE_FAIL=1; NEW_ACTIVE=active
rc=0
_mosdns_swap_verify "$WORK/new" amd64 "$NEWSHA" "$NEWSHA" local >/dev/null 2>&1 || rc=$?
[[ "$rc" != 0 && ! -e "$PDG_MOSDNS_BIN" && ! -e "$PDG_MOSDNS_ATTESTATION" ]] \
  && ok "装前不存在且候选失败 → 新 binary/证明均移除" \
  || bad "全新目标失败后留下半成品"

setup_old
rc=0
out=$(
  cp(){ return 1; }
  install(){ echo INSTALL-RAN; command install "$@"; }
  _mosdns_swap_verify "$WORK/new" amd64 "$NEWSHA" "$NEWSHA" local
) || rc=$?
[[ "$rc" != 0 && "$out" != *INSTALL-RAN* \
   && "$(sha256sum "$PDG_MOSDNS_BIN" | awk '{print $1}')" == "$OLDSHA" ]] \
  && ok "before-image 备份失败 → candidate install 从未执行" \
  || bad "无可靠退路时仍覆盖了 binary"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
