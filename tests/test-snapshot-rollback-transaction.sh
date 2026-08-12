#!/usr/bin/env bash
# Phase-specific partial snapshot failures must restore the current before-images.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
BOX="$WORK/box"; SERVICE_STATE="$WORK/service"
NFT_LIVE="$WORK/nft.live"; BASE_LIVE="$WORK/nft.live.baseline"
FAKE_ROUTE="$WORK/quic.route"
mkdir -p "$BOX" "$SERVICE_STATE"
export FAKE_ROUTE NFT_LIVE BASE_LIVE

for fn in _pdg_snapshot_restore_managed_files _pdg_capture_managed_files \
  _pdg_snapshot_failure_restore _pdg_switchcore_restore_nft_before; do
  sed -n "/^${fn}(){/,/^}/p" "$ROOT/deploy/bot/pdg.sh"
done >"$WORK/functions.sh"
# shellcheck disable=SC1090
source "$WORK/functions.sh"

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
cat >"$WORK/nfttxn.sh" <<'EOF'
pdg_nft_atomic_install(){
  local source="$1" target="$2" nft_exe="$3"
  "$nft_exe" -c -f "$source" >/dev/null 2>&1 || return 1
  cp "$source" "$target"
}
EOF
cat >"$WORK/quic-helper" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
case "${1:-}" in
  rollback-state)
    cp "${2:?}" "${PDG_QUIC_STATE:?}"
    printf 'current-route\n' >"${FAKE_ROUTE:?}";;
  status)
    grep -q '^MARK=0x504447$' "${PDG_QUIC_STATE:?}" \
      && grep -q '^current-route$' "${FAKE_ROUTE:?}";;
  *) exit 2;;
esac
EOF
chmod +x "$WORK/quic-helper"

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
    enable)
      echo enabled >"$SERVICE_STATE/$svc.enabled"
      (( now == 0 )) || echo active >"$SERVICE_STATE/$svc.active";;
    disable)
      echo disabled >"$SERVICE_STATE/$svc.enabled"
      (( now == 0 )) || echo inactive >"$SERVICE_STATE/$svc.active";;
    start) echo active >"$SERVICE_STATE/$svc.active";;
    stop) echo inactive >"$SERVICE_STATE/$svc.active";;
    daemon-reload) return 0;;
    *) return 2;;
  esac
}
fail(){ echo "[FAIL] $*" >&2; exit 1; }

export PDG_ROOT_PREFIX="$BOX"
export PDG_NFT_CONF="$BOX/etc/nftables.conf"
managed_paths=(
  etc/privdns-gateway/profile.env
  etc/privdns-gateway/backend
  etc/privdns-gateway/quic-routing.state
  etc/systemd/system/pdg-quic-routing.service
  usr/local/libexec/pdg-quic-routing.sh
  opt/pdg-bot/pdgprofile.py
  opt/pdg-bot/pdgmodel.py
  opt/pdg-bot/bot.py
  etc/mihomo/config.yaml
  etc/systemd/system/mihomo.service
)

reset_current(){
  local tmp="$1"
  rm -rf "$BOX" "$tmp"
  mkdir -p "$BOX/etc/privdns-gateway" "$BOX/etc/systemd/system" \
    "$BOX/etc/mihomo" "$BOX/usr/local/libexec" "$BOX/opt/pdg-bot" "$tmp"
  printf 'CURRENT-PROFILE\n' >"$BOX/etc/privdns-gateway/profile.env"
  printf 'mihomo\n' >"$BOX/etc/privdns-gateway/backend"
  printf 'MARK=0x504447\nMASK=0xffffffff\nTABLE=7895\nPRIORITY=17895\n' \
    >"$BOX/etc/privdns-gateway/quic-routing.state"
  printf 'CURRENT-QUIC-UNIT\n' >"$BOX/etc/systemd/system/pdg-quic-routing.service"
  cp "$WORK/quic-helper" "$BOX/usr/local/libexec/pdg-quic-routing.sh"
  printf '# parser\n' >"$BOX/opt/pdg-bot/pdgprofile.py"
  printf 'CURRENT-MODEL\n' >"$BOX/opt/pdg-bot/pdgmodel.py"
  printf 'CURRENT-BOT\n' >"$BOX/opt/pdg-bot/bot.py"
  printf 'CURRENT-MIHOMO\n' >"$BOX/etc/mihomo/config.yaml"
  printf 'CURRENT-MIHOMO-UNIT\n' >"$BOX/etc/systemd/system/mihomo.service"
  printf 'CURRENT-NFT\n' >"$BOX/etc/nftables.conf"
  printf 'table inet pdg { # current-live\n}\n' >"$BASE_LIVE"
  cp "$BASE_LIVE" "$NFT_LIVE"
  printf 'current-route\n' >"$FAKE_ROUTE"
  printf 'active\n' >"$SERVICE_STATE/pdg-quic-routing.active"
  printf 'enabled\n' >"$SERVICE_STATE/pdg-quic-routing.enabled"

  _pdg_capture_managed_files \
    "$tmp/current-managed" "$tmp/current-managed.manifest" \
    "${managed_paths[@]}" || fail "before-image capture"
  cp "$BOX/etc/privdns-gateway/quic-routing.state" "$tmp/q.before"
  cp "$BOX/etc/nftables.conf" "$tmp/nftables.current.before"
  cp "$BASE_LIVE" "$tmp/pdg.live.current.before"
  {
    printf 'table inet pdg\n'
    printf 'delete table inet pdg\n'
    cat "$BASE_LIVE"
  } >"$tmp/pdg.live.current.restore"
  cp "$WORK/nfttxn.sh" "$tmp/nfttxn.current.sh"
  : >"$tmp/quic-service.existed"
  : >"$tmp/quic-service.was-enabled"
  : >"$tmp/quic-service.was-active"
}

inject_phase_failure(){
  local phase="$1" tmp="$2"
  rm -f "$BOX/etc/privdns-gateway/quic-routing.state" "$FAKE_ROUTE"
  case "$phase" in
    live-apply)
      printf 'BROKEN-LIVE\n' >"$NFT_LIVE";&
    persistent-install)
      printf 'BROKEN-PERSISTENT\n' >"$BOX/etc/nftables.conf";&
    tree-apply)
      printf 'BROKEN-PROFILE\n' >"$BOX/etc/privdns-gateway/profile.env"
      printf 'BROKEN-BACKEND\n' >"$BOX/etc/privdns-gateway/backend"
      printf 'BROKEN-BOT\n' >"$BOX/opt/pdg-bot/bot.py";&
    optional-delete)
      rm -f "$BOX/etc/systemd/system/pdg-quic-routing.service" \
        "$BOX/usr/local/libexec/pdg-quic-routing.sh" \
        "$BOX/opt/pdg-bot/pdgprofile.py"
      rm -f "$BOX/opt/pdg-bot/pdgmodel.py"
      systemctl disable --now pdg-quic-routing >/dev/null;&
    legacy-cleanup)
      rm -f "$BOX/etc/mihomo/config.yaml" \
        "$BOX/etc/systemd/system/mihomo.service";;
    *) fail "unknown phase $phase";;
  esac
  _pdg_snapshot_failure_restore "$tmp" "$tmp/q.before" \
    "$tmp/current-managed/usr/local/libexec/pdg-quic-routing.sh" \
    "$tmp/current-managed/opt/pdg-bot/pdgprofile.py" \
    "$WORK/nft" 1 || fail "$phase: unified recovery returned failure"
}

assert_current_exact(){
  local phase="$1"
  [[ "$(cat "$BOX/etc/privdns-gateway/profile.env")" == CURRENT-PROFILE \
     && "$(cat "$BOX/etc/privdns-gateway/backend")" == mihomo \
     && "$(cat "$BOX/opt/pdg-bot/bot.py")" == CURRENT-BOT \
     && "$(cat "$BOX/opt/pdg-bot/pdgmodel.py")" == CURRENT-MODEL \
     && "$(cat "$BOX/etc/mihomo/config.yaml")" == CURRENT-MIHOMO \
     && "$(cat "$BOX/etc/systemd/system/mihomo.service")" == CURRENT-MIHOMO-UNIT \
     && "$(cat "$BOX/etc/nftables.conf")" == CURRENT-NFT \
     && "$(cat "$FAKE_ROUTE")" == current-route ]] \
    || fail "$phase: managed/current before-image drift"
  cmp -s "$BASE_LIVE" "$NFT_LIVE" || fail "$phase: live nft drift"
  [[ "$(cat "$SERVICE_STATE/pdg-quic-routing.active")" == active \
     && "$(cat "$SERVICE_STATE/pdg-quic-routing.enabled")" == enabled ]] \
    || fail "$phase: QUIC service state drift"
}

for phase in legacy-cleanup optional-delete tree-apply \
  persistent-install live-apply; do
  tmp="$WORK/txn-$phase"
  reset_current "$tmp"
  inject_phase_failure "$phase" "$tmp"
  assert_current_exact "$phase"
done

echo "[OK] snapshot rollback restores exact current state after five phase failures"
