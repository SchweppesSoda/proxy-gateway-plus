#!/usr/bin/env bash
# Snapshot candidates keep their schema while binding direct to this machine.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
export REPO_DIR="$ROOT"
sed -n '/^_pdg_snapshot_rebind_direct(){/,/^}/p' \
  "$ROOT/deploy/bot/pdg.sh" >"$WORK/function.sh"
# shellcheck disable=SC1090
source "$WORK/function.sh"

mkdir -p "$WORK/tree/etc/sing-box" "$WORK/tree/opt/pdg-bot"
cat >"$WORK/current.json" <<'JSON'
{
  "outbounds": [
    {"type": "direct", "tag": "KFC_JP"},
    {"type": "shadowsocks", "tag": "hk"}
  ],
  "route": {"rules": [], "final": "KFC_JP"}
}
JSON
cat >"$WORK/tree/etc/sing-box/config.json" <<'JSON'
{
  "outbounds": [
    {"type": "direct", "tag": "JP"},
    {"type": "shadowsocks", "tag": "hk"},
    {"type": "selector", "tag": "choice", "outbounds": ["JP", "hk"]}
  ],
  "route": {
    "rules": [{"domain_suffix": ["example.com"], "outbound": "JP"}],
    "final": "choice"
  },
  "_pdg": {"schema": 1, "mihomo": {}}
}
JSON
cat >"$WORK/tree/opt/pdg-bot/rulesets.json" <<'JSON'
{
  "foreign-direct": {
    "url": "https://rules.example/direct.txt",
    "outbound": "JP",
    "format": "source",
    "path": "/etc/sing-box/rs/foreign-direct.json"
  }
}
JSON

_pdg_snapshot_rebind_direct "$WORK/tree" "$WORK/current.json"
python3 - "$WORK/tree" <<'PY'
import json, pathlib, sys
tree = pathlib.Path(sys.argv[1])
model = json.loads((tree / "etc/sing-box/config.json").read_text())
rulesets = json.loads((tree / "opt/pdg-bot/rulesets.json").read_text())
assert model["_pdg"]["schema"] == 1
assert [item["tag"] for item in model["outbounds"] if item["type"] == "direct"] == ["KFC_JP"]
choice = next(item for item in model["outbounds"] if item["tag"] == "choice")
assert choice["outbounds"] == ["KFC_JP", "hk"]
assert model["route"]["rules"][0]["outbound"] == "KFC_JP"
assert rulesets["foreign-direct"]["outbound"] == "KFC_JP"
PY

cp "$WORK/tree/etc/sing-box/config.json" "$WORK/model.before"
cp "$WORK/tree/opt/pdg-bot/rulesets.json" "$WORK/rules.before"
python3 - "$WORK/tree/opt/pdg-bot/rulesets.json" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
data["foreign-direct"]["outbound"] = "missing"
json.dump(data, open(path, "w"), indent=2)
PY
cp "$WORK/tree/opt/pdg-bot/rulesets.json" "$WORK/invalid.before"
if _pdg_snapshot_rebind_direct "$WORK/tree" "$WORK/current.json" 2>/dev/null; then
  echo "[FAIL] invalid ruleset target was accepted" >&2
  exit 1
fi
cmp -s "$WORK/model.before" "$WORK/tree/etc/sing-box/config.json"
cmp -s "$WORK/invalid.before" "$WORK/tree/opt/pdg-bot/rulesets.json"

echo "[OK] snapshot direct rebind preserves schema, closes references, and fails atomically"
