#!/usr/bin/env bash
# Persistent and live nft before-images are independent, mandatory restores.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
SB="$WORK/sb"; mkdir -p "$SB/etc" "$WORK/wd"

sed -n '/^_pdg_switchcore_restore_nft_before(){/,/^}/p' \
  "$ROOT/deploy/bot/pdg.sh" \
  | sed 's#/etc/nftables[.]conf#$SB/etc/nftables.conf#g' >"$WORK/fn.sh"
grep -q '^_pdg_switchcore_restore_nft_before(){' "$WORK/fn.sh" \
  || { echo "[FAIL] helper extraction" >&2; exit 1; }

printf 'OLD-PERSISTENT\n' >"$WORK/bak"
printf 'table inet pdg {\n}\n' >"$WORK/live"
{
  printf 'table inet pdg\n'
  printf 'delete table inet pdg\n'
  cat "$WORK/live"
} >"$WORK/live-restore"
printf 'NEW-PERSISTENT\n' >"$SB/etc/nftables.conf"

pdg_nft_atomic_install(){
  [[ "${FAIL_PERSISTENT:-0}" != 1 ]] || return 71
  cp "$1" "$2"
}
nftfake(){
  if [[ "${1:-}" == -f ]]; then
    [[ "${FAIL_RUNTIME:-0}" != 1 ]] || return 72
    cp "$WORK/live" "$WORK/live-current"; return 0
  fi
  if [[ "$*" == "list table inet pdg" ]]; then
    cat "$WORK/live-current"; return 0
  fi
  return 2
}
source "$WORK/fn.sh"

run_restore(){
  _pdg_switchcore_restore_nft_before \
    "$WORK/wd" "$WORK/bak" nftfake 1 "$WORK/live-restore" "$WORK/live"
}

FAIL_PERSISTENT=1 run_restore >/dev/null 2>&1 \
  && { echo "[FAIL] persistent restore failure accepted" >&2; exit 1; }
printf 'NEW-PERSISTENT\n' >"$SB/etc/nftables.conf"
FAIL_RUNTIME=1 run_restore >/dev/null 2>&1 \
  && { echo "[FAIL] runtime restore failure accepted" >&2; exit 1; }
printf 'NEW-PERSISTENT\n' >"$SB/etc/nftables.conf"
run_restore >/dev/null || { echo "[FAIL] exact restore" >&2; exit 1; }
cmp -s "$WORK/bak" "$SB/etc/nftables.conf" \
  || { echo "[FAIL] persistent before-image mismatch" >&2; exit 1; }
cmp -s "$WORK/live" "$WORK/live-current" \
  || { echo "[FAIL] live before-image mismatch" >&2; exit 1; }

echo "[OK] switchcore nft rollback failures are hard and exact"
