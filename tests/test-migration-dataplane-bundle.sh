#!/usr/bin/env bash
# Update/migration must never render through a stale installed Python bundle.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
OLD="$WORK/old"; NEW="$WORK/new"; RUNTIME="$WORK/runtime"
mkdir -p "$OLD" "$NEW" "$RUNTIME"

cat >"$OLD/bot.py" <<'PY'
import json
def load(): return {}
def _render_mihomo_bytes(model):
    return json.dumps({"mode": "reject"}).encode(), {"unknown_proxies": []}
PY
cat >"$OLD/sb2mihomo.py" <<'PY'
OLD_CONVERTER = True
PY
cat >"$OLD/pdgprofile.py" <<'PY'
raise RuntimeError("old parser must not be imported")
PY
cat >"$OLD/pdgmodel.py" <<'PY'
raise RuntimeError("old model must not be imported")
PY

cat >"$NEW/pdg-bot.py" <<'PY'
import json, sb2mihomo
def load(): return {}
def _render_mihomo_bytes(model, rs_meta=None, mitm_domains=None):
    assert rs_meta is None
    assert mitm_domains is None
    return json.dumps({
        "tproxy-port": sb2mihomo.TPROXY,
        "sniffer": {"sniff": {"TLS": {"ports": [443, 10443]},
                              "HTTP": {"ports": [80]},
                              "QUIC": {"ports": [443]}}}
    }).encode(), {"unknown_proxies": []}
PY
cat >"$NEW/sb2mihomo.py" <<'PY'
TPROXY = 7895
def parse_quic_mode(value): return value
def parse_port_list(value, name="ports"): return value
PY
cat >"$NEW/pdgprofile.py" <<'PY'
import sb2mihomo
NEW_PARSER = sb2mihomo.TPROXY
PY
cat >"$NEW/pdgmodel.py" <<'PY'
SCHEMA_VERSION = 3
PY
cp "$OLD/"*.py "$RUNTIME/"

xfn(){
  awk -v fn="$1" '
    index($0, fn "(){") == 1 { inf = 1 }
    inf {
      print
      n = gsub(/\{/, "{"); m = gsub(/\}/, "}"); depth += n - m
      if (depth <= 0) exit
    }' "$ROOT/deploy/bot/pdg.sh"
}
{
  xfn _pdg_render_mihomo_candidate
  xfn _pdg_atomic_install_file
  xfn _pdg_install_dataplane_bundle
} >"$WORK/functions.sh"
# Redirect only the product runtime literal for this sandbox.
sed -i 's#dst=/opt/pdg-bot#dst="$RUNTIME"#' "$WORK/functions.sh"

export RUNTIME
# Explicit new bundle render must ignore OLD/bot.py even when it is first on
# PYTHONPATH.  The finished candidate demonstrates native TPROXY + exact
# profile-like sniffer ports.
PYTHONPATH="$OLD" bash -c "
set -uo pipefail
source '$WORK/functions.sh'
_pdg_render_mihomo_candidate '$WORK/candidate.json' '$NEW'
" || { echo "[FAIL] coherent new-bundle render" >&2; exit 1; }
python3 - "$WORK/candidate.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
assert c["tproxy-port"] == 7895
assert c["sniffer"]["sniff"]["TLS"]["ports"] == [443, 10443]
assert c["sniffer"]["sniff"]["HTTP"]["ports"] == [80]
assert c["sniffer"]["sniff"]["QUIC"]["ports"] == [443]
PY

# The runtime bundle deployment replaces old converter/parser/bot together,
# after validating all candidates.
bash -c "
set -uo pipefail
source '$WORK/functions.sh'
_pdg_install_dataplane_bundle '$NEW'
" || { echo "[FAIL] coherent runtime bundle install" >&2; exit 1; }
grep -q 'TPROXY = 7895' "$RUNTIME/sb2mihomo.py" || exit 1
grep -q 'NEW_PARSER' "$RUNTIME/pdgprofile.py" || exit 1
grep -q 'SCHEMA_VERSION = 3' "$RUNTIME/pdgmodel.py" || exit 1
grep -q 'tproxy-port' "$RUNTIME/bot.py" || exit 1
! grep -Rq 'OLD_CONVERTER\\|old parser' "$RUNTIME" || exit 1

# Guard the actual migration call sites against future priority regressions.
python3 - "$ROOT/deploy/bot/pdg.sh" <<'PY'
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
body = re.search(r"migrate_dataplane_profile\(\)\{(.*?)\n\}", s, re.S).group(1)
assert 'tool="$REPO_DIR/deploy/bot/pdgprofile.py"' in body
assert '_pdg_render_mihomo_candidate "$mcand" "$REPO_DIR/deploy/bot"' in body
assert '_switchcore_nft mihomo "$REPO_DIR"' in body
assert '_pdg_install_dataplane_bundle "$REPO_DIR/deploy/bot"' in body
assert "systemctl enable --now pdg-quic-routing" in body
assert "systemctl restart mihomo" in body
PY

echo "[OK] migration uses coherent checked-out bundle over stale runtime"
