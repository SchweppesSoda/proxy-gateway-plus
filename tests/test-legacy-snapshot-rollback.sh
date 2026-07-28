#!/usr/bin/env bash
# A pre-Mihomo snapshot must not retain newer managed config/unit assets.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
SB="$WORK/sb"; TREE="$WORK/tree"; PROOF="$WORK/proof"; REPO="$WORK/repo"
mkdir -p "$SB/etc/mihomo" "$SB/etc/systemd/system" \
  "$TREE/etc/sing-box" "$TREE/etc/systemd/system" \
  "$TREE/usr/local/bin" "$PROOF" "$REPO/lib"
printf '{"outbounds":[]}\n' >"$TREE/etc/sing-box/config.json"
printf '[Service]\nExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json\n' \
  >"$TREE/etc/systemd/system/sing-box.service"
printf '#!/usr/bin/env bash\nexit 0\n' >"$TREE/usr/local/bin/sing-box"
chmod +x "$TREE/usr/local/bin/sing-box"
printf 'MANAGED-CONFIG\n' >"$WORK/managed-config"
cat >"$REPO/lib/units.sh" <<'EOF'
pdg_unit_mihomo(){ printf 'MANAGED-UNIT\n'; }
EOF

{
  sed -n '/^_pdg_legacy_snapshot_mihomo_prove(){/,/^}/p' \
    "$ROOT/deploy/bot/pdg.sh"
  sed -n '/^_pdg_legacy_snapshot_mihomo_remove(){/,/^}/p' \
    "$ROOT/deploy/bot/pdg.sh"
} | sed \
  -e 's#/etc/mihomo/config.yaml#$SB/etc/mihomo/config.yaml#g' \
  -e 's#/etc/systemd/system/mihomo.service#$SB/etc/systemd/system/mihomo.service#g' \
  >"$WORK/functions.sh"
source "$WORK/functions.sh"
_pdg_render_mihomo_candidate(){ cp "$WORK/managed-config" "$1"; chmod 600 "$1"; }
export REPO_DIR="$REPO"

reset_managed(){
  printf 'MANAGED-CONFIG\n' >"$SB/etc/mihomo/config.yaml"
  printf 'MANAGED-UNIT\n' >"$SB/etc/systemd/system/mihomo.service"
  rm -f "$PROOF"/*
}
reset_managed
_pdg_legacy_snapshot_mihomo_prove "$TREE" "$PROOF" \
  || { echo "[FAIL] exact managed ownership proof" >&2; exit 1; }
_pdg_legacy_snapshot_mihomo_remove "$PROOF" \
  || { echo "[FAIL] exact managed cleanup" >&2; exit 1; }
[[ ! -e "$SB/etc/mihomo/config.yaml" \
   && ! -e "$SB/etc/systemd/system/mihomo.service" ]] \
  || { echo "[FAIL] newer managed Mihomo residue remains" >&2; exit 1; }

# Any ownership uncertainty is fail-closed and preserves the foreign file.
reset_managed
printf 'FOREIGN-CONFIG\n' >"$SB/etc/mihomo/config.yaml"
_pdg_legacy_snapshot_mihomo_prove "$TREE" "$PROOF" >/dev/null 2>&1 \
  && { echo "[FAIL] foreign config accepted" >&2; exit 1; }
[[ -e "$SB/etc/mihomo/config.yaml" ]] \
  || { echo "[FAIL] foreign config deleted" >&2; exit 1; }
reset_managed
printf 'FOREIGN-UNIT\n' >"$SB/etc/systemd/system/mihomo.service"
_pdg_legacy_snapshot_mihomo_prove "$TREE" "$PROOF" >/dev/null 2>&1 \
  && { echo "[FAIL] foreign unit accepted" >&2; exit 1; }
[[ -e "$SB/etc/systemd/system/mihomo.service" ]] \
  || { echo "[FAIL] foreign unit deleted" >&2; exit 1; }

# Integration contract: proof precedes tuple/file mutation, cleanup precedes
# extraction, and old model conversion uses the current coherent migration.
RB="$WORK/rollback.body"
sed -n '/^cmd_rollback(){/,/^}/p' "$ROOT/deploy/bot/pdg.sh" >"$RB"
line(){ grep -n -m1 "$1" "$RB" | cut -d: -f1; }
line_f(){ grep -nF -m1 "$1" "$RB" | cut -d: -f1; }
prove="$(line '_pdg_legacy_snapshot_mihomo_prove')"
tuple_remove="$(line '\"$cur_qhelper\" remove')"
cleanup="$(line '_pdg_legacy_snapshot_mihomo_remove')"
apply="$(line '_pdg_apply_snapshot_tree')"
[[ -n "$prove" && -n "$tuple_remove" && -n "$cleanup" && -n "$apply" \
   && "$prove" -lt "$tuple_remove" && "$cleanup" -lt "$apply" ]] \
  || { echo "[FAIL] rollback proof/cleanup ordering" >&2; exit 1; }
grep -q '_pdg_legacy_migrate_transaction' "$RB" \
  || { echo "[FAIL] old model not routed through transactional migration" >&2; exit 1; }
TX="$WORK/legacy-transaction.body"
sed -n '/^_pdg_legacy_migrate_transaction(){/,/^}/p' \
  "$ROOT/deploy/bot/pdg.sh" >"$TX"
grep -q 'migrate_dataplane_profile' "$TX" \
  || { echo "[FAIL] transaction does not call current migration" >&2; exit 1; }
line_tx_f(){ grep -nF -m1 "$1" "$TX" | cut -d: -f1; }
capture="$(line_tx_f '_pdg_legacy_migration_capture "$work" "$nftexe"')"
migrate="$(line_tx_f 'if ! migrate_dataplane_profile')"
unit="$(line_tx_f '_pdg_legacy_new_unit_ready "$work"')"
quic="$(line_tx_f 'if ! _pdg_legacy_quic_ready')"
equivalent="$(line_tx_f 'if ! _pdg_legacy_dataplane_equivalent')"
ownership="$(line_tx_f '_pdg_legacy_singbox_commit_proven "$work"')"
activate="$(line_tx_f '_core_kernel_activate mihomo sing-box')"
backend="$(line_tx_f '_pdg_atomic_install_file "$backend_source" "$backend_target"')"
readback="$(line_tx_f 'cmp -s "$backend_source" "$backend_target"')"
drop="$(line_tx_f '_pdg_drop_singbox_files "legacy transaction commit" 1 "$work/files"')"
committed="$(line_tx_f 'PDG_LEGACY_TX_RECOVERY=committed')"
[[ -n "$capture" && -n "$migrate" && -n "$unit" && -n "$quic" \
   && -n "$equivalent" && -n "$ownership" && -n "$activate" \
   && -n "$backend" && -n "$readback" && -n "$drop" && -n "$committed" \
   && "$capture" -lt "$migrate" && "$migrate" -lt "$unit" \
   && "$unit" -lt "$quic" && "$quic" -lt "$equivalent" \
   && "$equivalent" -lt "$ownership" && "$ownership" -lt "$activate" \
   && "$activate" -lt "$backend" && "$backend" -lt "$readback" \
   && "$readback" -lt "$drop" && "$drop" -lt "$committed" ]] \
  || { echo "[FAIL] legacy prepare/validate/commit ordering" >&2; exit 1; }

committed_gate="$(line_f 'if [[ "$legacy_migration_committed" == 1 ]]')"
generic_gate="$(line_f 'elif [[ "$legacy_migration_ok" == 1 ]]')"
preserve="$(line_f '保留原 backend/unit/bin/model')"
[[ -n "$committed_gate" && -n "$generic_gate" && -n "$preserve" \
   && "$committed_gate" -lt "$generic_gate" \
   && "$generic_gate" -lt "$preserve" ]] \
  || { echo "[FAIL] outer path can repeat legacy commit/drop/activation" >&2; exit 1; }

MIG="$WORK/migration.body"
sed -n '/^migrate_dataplane_profile(){/,/^}/p' "$ROOT/deploy/bot/pdg.sh" >"$MIG"
line_in_mig(){ grep -n -m1 "$1" "$MIG" | cut -d: -f1; }
route_unit="$(line_in_mig 'pdg-quic-routing.service')"
mihomo_unit="$(line_in_mig 'pdg_write_unit pdg_unit_mihomo')"
[[ -n "$route_unit" && -n "$mihomo_unit" && "$route_unit" -lt "$mihomo_unit" ]] \
  || { echo "[FAIL] regenerated Mihomo unit can precede QUIC unit" >&2; exit 1; }

echo "[OK] old sing-box snapshot removes only proven Mihomo assets and rebuilds coherent prerequisites"
