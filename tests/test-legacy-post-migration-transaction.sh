#!/usr/bin/env bash
# A successful legacy render is not committed until every post-migrate gate passes.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
BOX="$WORK/box"; REPO="$WORK/repo"
NFT_LIVE="$WORK/nft.live"; BASE_LIVE="$WORK/nft.live.baseline"
FAKE_ROUTE="$WORK/quic.route"
mkdir -p "$REPO/deploy/firewall" "$REPO/deploy/bot" "$REPO/lib"
export FAKE_ROUTE NFT_LIVE BASE_LIVE

for fn in _pdg_drop_singbox_files _pdg_singbox_is_ours _pdg_mktemp_dir \
  _pdg_snapshot_restore_managed_files _pdg_capture_managed_files \
  _pdg_legacy_quiesce_new_dataplane _pdg_legacy_activate_singbox \
  _pdg_legacy_migration_capture _pdg_legacy_migration_restore \
  _pdg_legacy_new_unit_ready _pdg_legacy_quic_ready \
  _pdg_legacy_dataplane_equivalent _pdg_legacy_singbox_commit_proven \
  _pdg_legacy_transaction_abort \
  _pdg_legacy_migrate_transaction _pdg_switchcore_restore_nft_before; do
  sed -n "/^${fn}(){/,/^}/p" "$ROOT/deploy/bot/pdg.sh"
done >"$WORK/functions.sh"
# shellcheck disable=SC1090
source "$WORK/functions.sh"

cat >"$REPO/deploy/firewall/pdg-quic-routing.sh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
case "${1:-}" in
  status)
    [[ "${FAIL_STAGE:-}" != quic \
       && -f "${PDG_QUIC_STATE:?}" && -f "${FAKE_ROUTE:?}" ]];;
  rollback-state)
    rm -f -- "${PDG_QUIC_STATE:?}" "${FAKE_ROUTE:?}";;
  *) exit 2;;
esac
EOF
chmod +x "$REPO/deploy/firewall/pdg-quic-routing.sh"
printf 'NEW-QUIC-UNIT\n' >"$REPO/deploy/firewall/pdg-quic-routing.service"
printf '# strict parser fixture\n' >"$REPO/deploy/bot/pdgprofile.py"
printf '# sibling fixture\n' >"$REPO/deploy/bot/sb2mihomo.py"
printf '# model fixture\n' >"$REPO/deploy/bot/pdgmodel.py"
printf '# equivalence source fixture\n' >"$REPO/deploy/bot/checks.py"
printf '# nft ownership fixture\n' >"$REPO/deploy/bot/nftscan.py"
cat >"$REPO/lib/units.sh" <<'EOF'
pdg_unit_mihomo(){ printf 'NEW-MIHOMO-UNIT\n'; }
EOF
# shellcheck disable=SC1090
source "$REPO/lib/units.sh"
cat >"$REPO/lib/singbox.sh" <<'EOF'
pdg_singbox_is_ours(){ [[ "${FAIL_STAGE:-}" != foreign-drop ]]; }
pdg_singbox_kept_paths(){
  printf '%s\n' "${PDG_ROOT_PREFIX:-}/etc/systemd/system/sing-box.service"
  printf '%s\n' "${PDG_ROOT_PREFIX:-}/usr/local/bin/sing-box"
}
pdg_singbox_why_not_ours(){ echo "foreign fixture"; }
pdg_singbox_mark_owned(){
  local marker="${PDG_ROOT_PREFIX:-}/etc/privdns-gateway/singbox.pdg-owned"
  printf 'PDG-SINGBOX-OWNED v1\n' >"$marker"
}
EOF
cat >"$REPO/lib/nfttxn.sh" <<'EOF'
pdg_nft_atomic_install(){
  local source="$1" target="$2" nft_exe="$3"
  "$nft_exe" -c -f "$source" >/dev/null 2>&1 || return 1
  mkdir -p "$(dirname "$target")" && cp "$source" "$target"
}
EOF
cat >"$WORK/nft" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
if [[ "${1:-}" == -c && "${2:-}" == -f ]]; then exit 0; fi
if [[ "${1:-}" == -f ]]; then
  cp "${BASE_LIVE:?}" "${NFT_LIVE:?}"; exit 0
fi
if [[ "$*" == "list table inet pdg" ]]; then
  [[ -f "${NFT_LIVE:?}" ]] || exit 1
  cat "$NFT_LIVE"; exit 0
fi
if [[ "$*" == "list tables" ]]; then
  [[ ! -f "${NFT_LIVE:?}" ]] || echo "table inet pdg"
  exit 0
fi
if [[ "$*" == "delete table inet pdg" ]]; then
  rm -f "${NFT_LIVE:?}"; exit 0
fi
exit 2
EOF
chmod +x "$WORK/nft"

declare -A SVC_ACTIVE=() SVC_ENABLED=()
systemctl(){
  local op="${1:-}" now=0 svc state
  shift || true
  if [[ "${1:-}" == --now ]]; then now=1; shift; fi
  svc="${1:-}"
  case "$op" in
    is-active)
      state="${SVC_ACTIVE[$svc]:-inactive}"
      echo "$state"; [[ "$state" == active ]];;
    is-enabled)
      state="${SVC_ENABLED[$svc]:-disabled}"
      echo "$state"; [[ "$state" == enabled || "$state" == enabled-runtime ]];;
    disable)
      SVC_ENABLED[$svc]=disabled
      (( now == 0 )) || SVC_ACTIVE[$svc]=inactive;;
    enable)
      SVC_ENABLED[$svc]=enabled
      (( now == 0 )) || SVC_ACTIVE[$svc]=active;;
    restart)
      SVC_ACTIVE[$svc]=active;;
    reset-failed) return 0;;
    daemon-reload)
      if [[ "${FAIL_STAGE:-}" == post-drop-daemon \
            && ! -e "$BOX/etc/systemd/system/sing-box.service" \
            && ! -e "$BOX/usr/local/bin/sing-box" ]]; then
        return 1
      fi
      return 0;;
    *) return 2;;
  esac
}

_pdg_nft_bin(){ echo "$WORK/nft"; }
_pdg_legacy_dataplane_equivalent(){
  [[ "${FAIL_STAGE:-}" != equivalence ]]
}
_core_kernel_activate(){
  systemctl enable --now "$1" >/dev/null \
    && systemctl disable --now "$2" >/dev/null
}
_core_kernel_stable(){
  [[ "${FAIL_STAGE:-}" != stable \
     && "$(systemctl is-active "$1" 2>/dev/null)" == active ]]
}
_pdg_atomic_install_file(){
  local source="$1" target="$2"
  [[ "${FAIL_STAGE:-}" != backend-write ]] || return 1
  mkdir -p "$(dirname "$target")" && cp "$source" "$target" || return 1
  if [[ "${FAIL_STAGE:-}" == backend-readback ]]; then
    printf 'CORRUPT\n' >"$target"
  fi
}
rm(){
  if [[ "${FAIL_STAGE:-}" == drop-rm \
        && " $* " == *" $BOX/etc/systemd/system/sing-box.service "* ]]; then
    command rm -f "$BOX/usr/local/bin/sing-box"
    return 1
  fi
  command rm "$@"
}
fail(){ echo "[FAIL] $*" >&2; exit 1; }

export PDG_ROOT_PREFIX="$BOX"
export PDG_NFT_CONF="$BOX/etc/nftables.conf"
export REPO_DIR="$REPO"

reset_legacy_target(){
  rm -rf "$BOX"
  mkdir -p "$BOX/etc/privdns-gateway" "$BOX/etc/sing-box" \
    "$BOX/etc/systemd/system" "$BOX/usr/local/bin" "$BOX/opt/pdg-bot"
  printf 'LEGACY-PROFILE\n' >"$BOX/etc/privdns-gateway/profile.env"
  printf 'managed\n' >"$BOX/etc/privdns-gateway/firewall-mode"
  printf 'singbox\n' >"$BOX/etc/privdns-gateway/backend"
  printf 'LEGACY-NFT\n' >"$BOX/etc/nftables.conf"
  printf '{"legacy":"model"}\n' >"$BOX/etc/sing-box/config.json"
  printf 'LEGACY-SINGBOX-UNIT\n' >"$BOX/etc/systemd/system/sing-box.service"
  printf '#!/bin/sh\nexit 0\n' >"$BOX/usr/local/bin/sing-box"
  chmod +x "$BOX/usr/local/bin/sing-box"
  printf 'OLD-BOT\n' >"$BOX/opt/pdg-bot/bot.py"
  printf 'OLD-CONVERTER\n' >"$BOX/opt/pdg-bot/sb2mihomo.py"
  printf 'OLD-MODEL\n' >"$BOX/opt/pdg-bot/pdgmodel.py"
  printf 'OLD-PROFILE-TOOL\n' >"$BOX/opt/pdg-bot/pdgprofile.py"
  printf 'table inet pdg { # legacy-live\n}\n' >"$BASE_LIVE"
  cp "$BASE_LIVE" "$NFT_LIVE"
  rm -f "$FAKE_ROUTE"
  SVC_ACTIVE=([mihomo]=active [pdg-quic-routing]=active [sing-box]=inactive)
  SVC_ENABLED=([mihomo]=enabled [pdg-quic-routing]=enabled [sing-box]=disabled)
}

migrate_dataplane_profile(){
  local pfx="$PDG_ROOT_PREFIX"
  printf 'NEW-PROFILE\n' >"$pfx/etc/privdns-gateway/profile.env"
  printf 'NEW-BOT\n' >"$pfx/opt/pdg-bot/bot.py"
  printf 'NEW-CONVERTER\n' >"$pfx/opt/pdg-bot/sb2mihomo.py"
  printf 'NEW-MODEL\n' >"$pfx/opt/pdg-bot/pdgmodel.py"
  printf 'NEW-PROFILE-TOOL\n' >"$pfx/opt/pdg-bot/pdgprofile.py"
  mkdir -p "$pfx/usr/local/libexec" "$pfx/etc/mihomo"
  cp "$REPO/deploy/firewall/pdg-quic-routing.sh" \
    "$pfx/usr/local/libexec/pdg-quic-routing.sh"
  chmod +x "$pfx/usr/local/libexec/pdg-quic-routing.sh"
  cp "$REPO/deploy/firewall/pdg-quic-routing.service" \
    "$pfx/etc/systemd/system/pdg-quic-routing.service"
  printf 'NEW-MIHOMO\n' >"$pfx/etc/mihomo/config.yaml"
  if [[ "${FAIL_STAGE:-}" == unit ]]; then
    printf 'CORRUPT-MIHOMO-UNIT\n' >"$pfx/etc/systemd/system/mihomo.service"
  else
    pdg_unit_mihomo >"$pfx/etc/systemd/system/mihomo.service"
  fi
  printf 'NEW-NFT\n' >"$PDG_NFT_CONF"
  printf 'table inet pdg { # new-live\n}\n' >"$NFT_LIVE"
  printf 'MARK=0x504447\nMASK=0xffffffff\nTABLE=7895\nPRIORITY=17895\n' \
    >"$pfx/etc/privdns-gateway/quic-routing.state"
  printf 'new-route\n' >"$FAKE_ROUTE"
  systemctl enable --now pdg-quic-routing >/dev/null
  systemctl restart mihomo >/dev/null
}

assert_legacy_recovered(){
  local stage="$1"
  [[ "$(cat "$BOX/etc/privdns-gateway/profile.env")" == LEGACY-PROFILE \
     && "$(cat "$BOX/etc/privdns-gateway/backend")" == singbox \
     && "$(cat "$BOX/etc/nftables.conf")" == LEGACY-NFT ]] \
    || fail "$stage: profile/backend/persistent nft drift"
  cmp -s "$BASE_LIVE" "$NFT_LIVE" || fail "$stage: live nft drift"
  [[ "$(cat "$BOX/opt/pdg-bot/bot.py")" == OLD-BOT \
     && "$(cat "$BOX/opt/pdg-bot/sb2mihomo.py")" == OLD-CONVERTER \
     && "$(cat "$BOX/opt/pdg-bot/pdgmodel.py")" == OLD-MODEL \
     && "$(cat "$BOX/opt/pdg-bot/pdgprofile.py")" == OLD-PROFILE-TOOL ]] \
    || fail "$stage: coherent runtime bundle drift"
  [[ "$(cat "$BOX/etc/sing-box/config.json")" == '{"legacy":"model"}' \
     && "$(cat "$BOX/etc/systemd/system/sing-box.service")" == LEGACY-SINGBOX-UNIT \
     && -x "$BOX/usr/local/bin/sing-box" \
     && ! -e "$BOX/etc/privdns-gateway/singbox.pdg-owned" ]] \
    || fail "$stage: sing-box recovery assets drift"
  [[ ! -e "$BOX/etc/mihomo/config.yaml" \
     && ! -e "$BOX/etc/systemd/system/mihomo.service" \
     && ! -e "$BOX/etc/systemd/system/pdg-quic-routing.service" \
     && ! -e "$BOX/usr/local/libexec/pdg-quic-routing.sh" \
     && ! -e "$BOX/etc/privdns-gateway/quic-routing.state" \
     && ! -e "$FAKE_ROUTE" ]] \
    || fail "$stage: Mihomo/QUIC residue remains"
  [[ "${SVC_ACTIVE[mihomo]}" != active \
     && "${SVC_ENABLED[mihomo]}" != enabled \
     && "${SVC_ACTIVE[pdg-quic-routing]}" != active \
     && "${SVC_ENABLED[pdg-quic-routing]}" != enabled \
     && "${SVC_ACTIVE[sing-box]}" == active \
     && "${SVC_ENABLED[sing-box]}" == enabled \
     && "$PDG_LEGACY_TX_RECOVERY" == ok ]] \
    || fail "$stage: service recovery/read-back failed"
}

export FAIL_STAGE
declare -A EXPECTED_ABORT=(
  [unit]="Mihomo unit prepare/read-back"
  [quic]="QUIC service/status"
  [equivalence]="profile/persistent/live nft 与 Mihomo 等价性"
  [stable]="Mihomo stable activation"
  [backend-write]="backend atomic write"
  [backend-readback]="backend read-back"
  [drop-rm]="sing-box owned runtime drop"
  [foreign-drop]="sing-box ownership/capture proof"
  [post-drop-daemon]="sing-box owned runtime drop"
)
fault_stages=()
if [[ "${PDG_POST_TX_SKIP_FAULTS:-0}" == 1 ]]; then
  :
elif [[ -n "${PDG_POST_TX_STAGES:-}" ]]; then
  read -r -a fault_stages <<<"$PDG_POST_TX_STAGES"
else
  fault_stages=(unit quic equivalence stable backend-write backend-readback
    drop-rm foreign-drop post-drop-daemon)
fi
for FAIL_STAGE in "${fault_stages[@]}"; do
  echo "[RUN] post-migrate fault: $FAIL_STAGE"
  reset_legacy_target
  if _pdg_legacy_migrate_transaction >"$WORK/$FAIL_STAGE.out" 2>&1; then
    fail "$FAIL_STAGE: post-migrate failure returned success"
  fi
  grep -Fq "${EXPECTED_ABORT[$FAIL_STAGE]}" "$WORK/$FAIL_STAGE.out" \
    || fail "$FAIL_STAGE: wrong gate | $(cat "$WORK/$FAIL_STAGE.out")"
  assert_legacy_recovered "$FAIL_STAGE"
done

if [[ "${PDG_POST_TX_SKIP_SUCCESS:-0}" != 1 ]]; then
  echo "[RUN] post-migrate success commit"
  FAIL_STAGE=success
  reset_legacy_target
  if ! _pdg_legacy_migrate_transaction >"$WORK/success.out" 2>&1; then
    success_out="$(cat "$WORK/success.out")"
    fail "success: complete prepare/validate/commit failed | $success_out"
  fi
  [[ "$(cat "$BOX/etc/privdns-gateway/backend")" == mihomo \
     && ! -e "$BOX/etc/systemd/system/sing-box.service" \
     && ! -e "$BOX/usr/local/bin/sing-box" \
     && ! -e "$BOX/etc/privdns-gateway/singbox.pdg-owned" \
     && -f "$BOX/etc/sing-box/config.json" \
     && "${SVC_ACTIVE[mihomo]}" == active \
     && "${SVC_ENABLED[mihomo]}" == enabled \
     && "${SVC_ACTIVE[pdg-quic-routing]}" == active \
     && "${SVC_ENABLED[pdg-quic-routing]}" == enabled \
     && "${SVC_ACTIVE[sing-box]}" != active \
     && "${SVC_ENABLED[sing-box]}" != enabled \
     && "$PDG_LEGACY_TX_RECOVERY" == committed ]] \
    || fail "success: committed target/read-back mismatch"
fi

echo "[OK] legacy post-migrate transaction restores ${#fault_stages[@]} fault stages and commits only after all gates"
