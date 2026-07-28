#!/usr/bin/env python3
"""Lifecycle ordering and rollback gates for the profile-owned data plane."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
install = (ROOT / "install.sh").read_text(encoding="utf-8")
pdg = (ROOT / "deploy" / "bot" / "pdg.sh").read_text(encoding="utf-8")
units = (ROOT / "lib" / "units.sh").read_text(encoding="utf-8")
restore = (ROOT / "deploy" / "cert" /
           "proxy-gateway-restore-firewall.sh").read_text(encoding="utf-8")
uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")


def body(source, name):
    match = re.search(r"^" + re.escape(name) + r"\(\)\{", source, re.M)
    assert match, name
    following = re.search(r"^[A-Za-z_][A-Za-z0-9_]*\(\)\{",
                          source[match.end():], re.M)
    end = match.end() + following.start() if following else len(source)
    return source[match.start():end]


# Boot/install: route helper is a hard prerequisite and exact status is gated
# before Mihomo. Commit status runs after service stability and before INSTALL_OK.
route_start = install.index("systemctl enable --now pdg-quic-routing")
route_status = install.index(
    "/usr/local/libexec/pdg-quic-routing.sh status", route_start)
core_start = install.index('systemctl enable --now mosdns "$CORE_SVC"', route_status)
assert route_start < route_status < core_start
commit_status = install.rindex(
    "/usr/local/libexec/pdg-quic-routing.sh status")
assert install.index("svc_ok=0") < commit_status < install.index("INSTALL_OK=1")
assert "PLAT_SVCS=(pdg-quic-routing mosdns" in install
assert "Requires=pdg-quic-routing.service" in units
assert re.search(
    r"After=.*pdg-quic-routing\.service", units)
assert 'canonical-ipv4 "$SERVER_IP"' in install
assert 'canonical-hostname "$DOT_DOMAIN"' in install
assert "--listener-preflight lines" in install

# Central nft transaction captures/restores both nft and trusted route state.
switch = body(pdg, "_switchcore_nft")
assert "quic-routing.state.before" in switch
assert 'rollback-state "$qbefore"' in switch
assert "_pdg_switchcore_restore_nft_before" in switch
assert "before-image 回滚不完整" in switch
assert "pdg_nft_atomic_install" in switch
assert "--listener-preflight render-nft" in switch
switch_nft_restore = body(pdg, "_pdg_switchcore_restore_nft_before")
assert 'cmp -s "$bak" "$nft_target"' in switch_nft_restore
assert 'cmp -s "$livebak" "$now"' in switch_nft_restore
assert "|| true" not in "\n".join(
    line for line in (switch + switch_nft_restore).splitlines()
    if "restore_nft_before" in line or '"$nftexe" -f "$live_restore"' in line)

# Restart validates prerequisites before writes, snapshots all three before
# images, and restores them on config/apply and post-restart stability failures.
restart = body(pdg, "cmd_restart")
assert restart.index("systemctl enable --now pdg-quic-routing") < restart.index(
    "_pdg_atomic_install_file")
for marker in ("config.before", "nft.before", "state.before"):
    assert marker in restart
assert restart.count("_pdg_restart_restore_before") >= 3
assert restart.index("_switchcore_nft mihomo") < restart.index(
    'systemctl restart "$s"')
restore_before = body(pdg, "_pdg_restart_restore_before")
assert restore_before.index("rollback-state") < restore_before.index(
    "pdg_nft_atomic_install")
assert restore_before.index("pdg_nft_atomic_install") < restore_before.index(
    "config.before")

# Snapshot restore allows the exact route helper member, proves/removes current
# tuple B before file application, removes exact optional files absent snapshot
# A, and treats live nft/equivalence failures as hard incomplete rollback.
snapshot = body(pdg, "cmd_snapshot")
rollback = body(pdg, "cmd_rollback")
assert "usr/local/libexec/pdg-quic-routing.sh" in snapshot
assert "^usr/local/libexec/pdg-quic-routing[.]sh$" in rollback
assert rollback.index('"$cur_qhelper" status') < rollback.index(
    "_pdg_apply_snapshot_tree")
assert rollback.index('"$cur_qhelper" remove') < rollback.index(
    "_pdg_apply_snapshot_tree")
assert 'bash "$snap_qhelper" preflight' in rollback
assert "_pdg_snapshot_abort" in rollback
for managed in (
    "etc/systemd/system/pdg-quic-routing.service",
    "usr/local/libexec/pdg-quic-routing.sh",
    "etc/privdns-gateway/quic-routing.state",
    "opt/pdg-bot/pdgprofile.py",
):
    assert managed in rollback
assert '"$rb_nft" -c -f "$tree/etc/nftables.conf"' in rollback
assert '"$rb_nft" -f /etc/nftables.conf' in rollback
assert "checks.check_dataplane_profile()" in rollback
legacy_tx = body(pdg, "_pdg_legacy_migrate_transaction")
legacy_restore = body(pdg, "_pdg_legacy_migration_restore")
assert "migrate_dataplane_profile" in legacy_tx
legacy_gates = (
    '_pdg_legacy_migration_capture "$work" "$nftexe"',
    "migrate_dataplane_profile",
    '_pdg_legacy_new_unit_ready "$work"',
    "_pdg_legacy_quic_ready",
    "_pdg_legacy_dataplane_equivalent",
    '_pdg_legacy_singbox_commit_proven "$work"',
    "_core_kernel_activate mihomo sing-box",
    "_core_kernel_stable mihomo",
    '_pdg_atomic_install_file "$backend_source" "$backend_target"',
    'cmp -s "$backend_source" "$backend_target"',
    '_pdg_drop_singbox_files "legacy transaction commit" 1 "$work/files"',
    "PDG_LEGACY_TX_RECOVERY=committed",
)
for before, after in zip(legacy_gates, legacy_gates[1:]):
    assert legacy_tx.index(before) < legacy_tx.index(after)
assert legacy_tx.count("_pdg_legacy_transaction_abort") >= 7
assert rollback.index('if [[ "$legacy_migration_committed" == 1 ]]') < rollback.index(
    'elif [[ "$legacy_migration_ok" == 1 ]]')
assert "_pdg_legacy_quiesce_new_dataplane" in legacy_restore
assert "_pdg_legacy_activate_singbox" in legacy_restore
legacy_abort = body(pdg, "_pdg_legacy_transaction_abort")
assert "_pdg_legacy_migration_restore" in legacy_abort
assert "before-image 保留于 $work" in legacy_abort
snapshot_restore = body(pdg, "_pdg_snapshot_failure_restore")
assert 'rollback-state "$qbefore"' in snapshot_restore
assert "_pdg_snapshot_restore_managed_files" in snapshot_restore
assert "_pdg_switchcore_restore_nft_before" in snapshot_restore
for injected_failure in (
    '_pdg_legacy_snapshot_mihomo_remove "$tmp"',
    'rm -f -- "/$mp"',
    '! _pdg_apply_snapshot_tree',
    'pdg_nft_atomic_install "$tree/etc/nftables.conf"',
    '"$rb_nft" -f /etc/nftables.conf',
):
    failure_at = rollback.index(injected_failure)
    assert "_pdg_snapshot_abort" in rollback[failure_at:failure_at + 850], (
        "snapshot failure lacks unified recovery: " + injected_failure)

# Status consumes the same complete checker and returns nonzero on missing or
# stale persistent/live nft, Mihomo, or route state.
status = body(pdg, "cmd_status")
assert "checks.check_dataplane_profile()" in status
assert "FAILED(" in status
assert 'required_svcs="$(_pdg_required_svcs)"' in status
assert re.search(
    r'\[\[ " \$required_svcs " == \*" \$s "\* && "\$_st" != active \]\]'
    r'; then\s+status_failed=1', status)
assert 'return "$status_failed"' in status

# Update and migration both re-apply/verify route, then restart Mihomo.
update = body(pdg, "cmd_update")
assert update.index("systemctl enable --now pdg-quic-routing") < update.index(
    "systemctl restart mihomo")
migration = body(pdg, "migrate_dataplane_profile")
assert '_switchcore_nft mihomo "$REPO_DIR"' in migration
assert migration.index("systemctl enable --now pdg-quic-routing") < migration.index(
    "systemctl restart mihomo")

# Cert restoration re-applies both planes and propagates failures.
assert '"$NFT" -f /etc/nftables.conf' in restore
assert '"$QUIC" apply' in restore and '"$QUIC" status' in restore
assert "|| true" not in "\n".join(
    line for line in restore.splitlines()
    if '"$NFT" -f' in line or '"$QUIC"' in line)

# Uninstall always stops+disables the unit; deletion occurs only after the
# read-only no-state/no-tuple proof. Persistent nft write is validated+atomic.
assert "systemctl stop pdg-quic-routing" in uninstall
assert "systemctl disable pdg-quic-routing" in uninstall
assert "cleanup-status" in uninstall
delete_if = uninstall.index('if [[ "$QUIC_CLEAN" == 1 ]]')
assert delete_if < uninstall.index(
    "rm -f /etc/systemd/system/pdg-quic-routing.service")
assert "pdg_nft_atomic_install" in uninstall

print("[OK] install/restart/update/migration/cert/uninstall data-plane lifecycle gates")
