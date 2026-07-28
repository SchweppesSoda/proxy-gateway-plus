#!/usr/bin/env bash
# Legacy rollback conversion failures must restore the already-applied old target.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
BOX="$WORK/box"; REPO="$WORK/repo"; SERVICE_STATE="$WORK/services"
NFT_LIVE="$WORK/nft.live"; BASE_LIVE="$WORK/nft.live.baseline"
FAKE_ROUTE="$WORK/quic.route"
mkdir -p "$BOX" "$SERVICE_STATE" "$REPO/deploy/firewall" \
  "$REPO/deploy/bot" "$REPO/lib"
export FAKE_ROUTE

for fn in _pdg_mktemp_dir _pdg_snapshot_restore_managed_files \
  _pdg_capture_managed_files _pdg_legacy_quiesce_new_dataplane \
  _pdg_legacy_activate_singbox _pdg_legacy_migration_capture \
  _pdg_legacy_migration_restore _pdg_legacy_transaction_abort \
  _pdg_legacy_migrate_transaction \
  _pdg_switchcore_restore_nft_before; do
  sed -n "/^${fn}(){/,/^}/p" "$ROOT/deploy/bot/pdg.sh"
done >"$WORK/functions.sh"
# shellcheck disable=SC1090
source "$WORK/functions.sh"

cat >"$REPO/deploy/firewall/pdg-quic-routing.sh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
[[ "${1:-}" == rollback-state ]] || exit 2
rm -f -- "${PDG_QUIC_STATE:?}" "${FAKE_ROUTE:?}"
EOF
chmod +x "$REPO/deploy/firewall/pdg-quic-routing.sh"
printf '# strict parser fixture\n' >"$REPO/deploy/bot/pdgprofile.py"
printf '# sibling fixture\n' >"$REPO/deploy/bot/sb2mihomo.py"
cat >"$REPO/lib/nfttxn.sh" <<'EOF'
pdg_nft_atomic_install(){
  local source="$1" target="$2" nft_exe="$3"
  "$nft_exe" -c -f "$source" >/dev/null 2>&1 || return 1
  mkdir -p "$(dirname "$target")"
  cp "$source" "$target"
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
export NFT_LIVE BASE_LIVE

systemctl(){
  local op="${1:-}" now=0 svc state
  shift || true
  if [[ "${1:-}" == --now ]]; then now=1; shift; fi
  svc="${1:-}"
  case "$op" in
    is-active)
      state="$(cat "$SERVICE_STATE/$svc.active" 2>/dev/null || echo inactive)"
      echo "$state"; [[ "$state" == active ]];;
    is-enabled)
      state="$(cat "$SERVICE_STATE/$svc.enabled" 2>/dev/null || echo disabled)"
      echo "$state"; [[ "$state" == enabled || "$state" == enabled-runtime ]];;
    disable)
      echo disabled >"$SERVICE_STATE/$svc.enabled"
      (( now == 0 )) || echo inactive >"$SERVICE_STATE/$svc.active";;
    enable)
      echo enabled >"$SERVICE_STATE/$svc.enabled"
      (( now == 0 )) || echo active >"$SERVICE_STATE/$svc.active";;
    restart)
      echo active >"$SERVICE_STATE/$svc.active";;
    daemon-reload) return 0;;
    *) return 2;;
  esac
}
_pdg_nft_bin(){ echo "$WORK/nft"; }
fail(){ echo "[FAIL] $*" >&2; exit 1; }

PDG_ROOT_PREFIX="$BOX"
PDG_NFT_CONF="$BOX/etc/nftables.conf"
export REPO_DIR="$REPO"

reset_legacy_target(){
  rm -rf "$BOX"; mkdir -p "$BOX/etc/privdns-gateway" \
    "$BOX/etc/sing-box" "$BOX/etc/systemd/system" \
    "$BOX/usr/local/bin" "$BOX/opt/pdg-bot"
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
  printf 'OLD-PROFILE-TOOL\n' >"$BOX/opt/pdg-bot/pdgprofile.py"
  printf 'table inet pdg { # legacy-live\n}\n' >"$BASE_LIVE"
  cp "$BASE_LIVE" "$NFT_LIVE"
  rm -f "$FAKE_ROUTE"
  printf 'active\n' >"$SERVICE_STATE/mihomo.active"
  printf 'enabled\n' >"$SERVICE_STATE/mihomo.enabled"
  printf 'active\n' >"$SERVICE_STATE/pdg-quic-routing.active"
  printf 'enabled\n' >"$SERVICE_STATE/pdg-quic-routing.enabled"
  printf 'inactive\n' >"$SERVICE_STATE/sing-box.active"
  printf 'disabled\n' >"$SERVICE_STATE/sing-box.enabled"
}

migrate_dataplane_profile(){
  local pfx="$PDG_ROOT_PREFIX"
  printf 'NEW-PROFILE\n' >"$pfx/etc/privdns-gateway/profile.env"
  printf 'NEW-BOT\n' >"$pfx/opt/pdg-bot/bot.py"
  printf 'NEW-CONVERTER\n' >"$pfx/opt/pdg-bot/sb2mihomo.py"
  printf 'NEW-PROFILE-TOOL\n' >"$pfx/opt/pdg-bot/pdgprofile.py"
  mkdir -p "$pfx/usr/local/libexec" "$pfx/etc/mihomo"
  printf 'NEW-HELPER\n' >"$pfx/usr/local/libexec/pdg-quic-routing.sh"
  printf 'NEW-QUIC-UNIT\n' >"$pfx/etc/systemd/system/pdg-quic-routing.service"
  printf 'NEW-MIHOMO\n' >"$pfx/etc/mihomo/config.yaml"
  printf 'NEW-MIHOMO-UNIT\n' >"$pfx/etc/systemd/system/mihomo.service"
  printf 'NEW-NFT\n' >"$PDG_NFT_CONF"
  printf 'table inet pdg { # new-live\n}\n' >"$NFT_LIVE"
  [[ "$FAIL_STAGE" != nft ]] || return 81
  printf 'MARK=0x504447\nMASK=0xffffffff\nTABLE=7895\nPRIORITY=17895\n' \
    >"$pfx/etc/privdns-gateway/quic-routing.state"
  printf 'new-route\n' >"$FAKE_ROUTE"
  systemctl enable --now pdg-quic-routing >/dev/null
  [[ "$FAIL_STAGE" != quic-start ]] || return 82
  systemctl restart mihomo >/dev/null
  [[ "$FAIL_STAGE" != mihomo-restart ]] || return 83
  echo inactive >"$SERVICE_STATE/pdg-quic-routing.active"
  return 84
}

assert_legacy_recovered(){
  [[ "$(cat "$BOX/etc/privdns-gateway/profile.env")" == LEGACY-PROFILE \
     && "$(cat "$BOX/etc/privdns-gateway/backend")" == singbox \
     && "$(cat "$BOX/etc/nftables.conf")" == LEGACY-NFT ]] \
    || fail "$1: profile/backend/persistent nft drift"
  cmp -s "$BASE_LIVE" "$NFT_LIVE" || fail "$1: live nft drift"
  [[ "$(cat "$BOX/opt/pdg-bot/bot.py")" == OLD-BOT \
     && "$(cat "$BOX/opt/pdg-bot/sb2mihomo.py")" == OLD-CONVERTER \
     && "$(cat "$BOX/opt/pdg-bot/pdgprofile.py")" == OLD-PROFILE-TOOL ]] \
    || fail "$1: coherent runtime bundle drift"
  [[ "$(cat "$BOX/etc/sing-box/config.json")" == '{"legacy":"model"}' \
     && "$(cat "$BOX/etc/systemd/system/sing-box.service")" == LEGACY-SINGBOX-UNIT \
     && -x "$BOX/usr/local/bin/sing-box" ]] \
    || fail "$1: sing-box recovery assets drift"
  [[ ! -e "$BOX/etc/mihomo/config.yaml" \
     && ! -e "$BOX/etc/systemd/system/mihomo.service" \
     && ! -e "$BOX/etc/systemd/system/pdg-quic-routing.service" \
     && ! -e "$BOX/usr/local/libexec/pdg-quic-routing.sh" \
     && ! -e "$BOX/etc/privdns-gateway/quic-routing.state" \
     && ! -e "$FAKE_ROUTE" ]] \
    || fail "$1: incomplete Mihomo/QUIC residue"
  [[ "$(cat "$SERVICE_STATE/mihomo.active")" != active \
     && "$(cat "$SERVICE_STATE/mihomo.enabled")" != enabled \
     && "$(cat "$SERVICE_STATE/pdg-quic-routing.active")" != active \
     && "$(cat "$SERVICE_STATE/pdg-quic-routing.enabled")" != enabled \
     && "$(cat "$SERVICE_STATE/sing-box.active")" == active \
     && "$(cat "$SERVICE_STATE/sing-box.enabled")" == enabled \
     && "$PDG_LEGACY_TX_RECOVERY" == ok ]] \
    || fail "$1: service recovery/readback failed"
}

for FAIL_STAGE in nft quic-start mihomo-restart final-liveness; do
  reset_legacy_target
  _pdg_legacy_migrate_transaction >/dev/null 2>&1 \
    && fail "$FAIL_STAGE: migration failure returned success"
  assert_legacy_recovered "$FAIL_STAGE"
done

echo "[OK] legacy migration transaction restores old target at four internal failure gates"
