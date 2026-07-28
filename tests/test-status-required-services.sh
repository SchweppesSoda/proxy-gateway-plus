#!/usr/bin/env bash
# Required service liveness is part of `pdg status`, not just display text.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

sed -n '/^cmd_status(){/,/^}/p' "$ROOT/deploy/bot/pdg.sh" \
  >"$WORK/cmd-status.sh"
# shellcheck disable=SC1090
source "$WORK/cmd-status.sh"

PROFILE_ENV="$WORK/profile.env"
REPO_DIR="$WORK/repo"; mkdir -p "$REPO_DIR"
: >"$PROFILE_ENV"; : >"$WORK/profile-tool"
c_g(){ :; }
_pdg_core(){ echo mihomo; }
_pdg_bot_cred(){ echo unset; }
_pdg_platform(){ echo android; }
_pdg_platform_present(){ return 0; }
_pdg_svcs(){ echo "pdg-quic-routing mosdns mihomo pdg-bot"; }
_pdg_required_svcs(){ echo "pdg-quic-routing mosdns mihomo"; }
_pdg_profile_tool(){ echo "$WORK/profile-tool"; }
pdg_lowmem_current(){ echo 0; }
jq(){ return 1; }
ss(){ return 0; }
python3(){
  cat >/dev/null
  if (( $# >= 3 )); then
    echo 'tproxy|443|80|0x504447/0xffffffff|7895|17895'
  else
    echo 'ok|透明数据面|profile/nft/Mihomo/route 一致'
  fi
}
systemctl(){
  local op="${1:-}" service="${2:-}"
  [[ "$op" == is-active ]] || return 1
  case "$service" in
    mosdns) echo "${MOS_STATE:-active}";;
    mihomo) echo "${MIHOMO_STATE:-active}";;
    pdg-quic-routing) echo active;;
    *) echo inactive; return 3;;
  esac
}
fail(){ echo "[FAIL] $*" >&2; exit 1; }

MOS_STATE=active MIHOMO_STATE=active cmd_status >/dev/null \
  || fail "all required services active returned failure"
MOS_STATE=inactive MIHOMO_STATE=active cmd_status >/dev/null \
  && fail "inactive mosdns returned success"
MOS_STATE=active MIHOMO_STATE=inactive cmd_status >/dev/null \
  && fail "inactive Mihomo returned success"

echo "[OK] pdg status fails on inactive required mosdns/Mihomo services"
