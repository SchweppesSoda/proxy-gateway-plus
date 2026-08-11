#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib/versions.sh
source "$ROOT/lib/versions.sh"
WORK="$(mktemp -d)"
PID=""
cleanup(){
  if [[ -n "$PID" ]]; then
    kill "$PID" 2>/dev/null || true
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT
fail(){ echo "[FAIL] $*" >&2; exit 1; }

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) fail "unsupported architecture" ;;
esac

curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VER}/mihomo-linux-${ARCH}-${MIHOMO_VER}.gz" \
  -o "$WORK/mihomo.gz" || fail "mihomo download failed"
pdg_verify_sha256 "$WORK/mihomo.gz" "${PDG_SHA256[mihomo-$ARCH]:-}" "mihomo template runtime" \
  || fail "mihomo SHA256 mismatch"
gunzip -c "$WORK/mihomo.gz" >"$WORK/mihomo" || fail "mihomo extraction failed"
chmod 755 "$WORK/mihomo"

curl -fsSL "https://github.com/IrineSistiana/mosdns/releases/download/${MOSDNS_VER}/mosdns-linux-${ARCH}.zip" \
  -o "$WORK/mosdns.zip" || fail "mosdns download failed"
pdg_verify_sha256 "$WORK/mosdns.zip" "${PDG_SHA256[mosdns-$ARCH]:-}" "mosdns template runtime" \
  || fail "mosdns SHA256 mismatch"
(cd "$WORK" && unzip -q mosdns.zip) || fail "mosdns extraction failed"
chmod 755 "$WORK/mosdns"

export PATH="$WORK:$PATH"
pdg_mihomo_is_version "$MIHOMO_VER" \
  || fail "downloaded Mihomo version does not exactly match the pin"
pdg_mosdns_is_version "$MOSDNS_VER" \
  || fail "downloaded MosDNS version does not exactly match the pin"

mkdir -p "$WORK/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -keyout "$WORK/certs/privkey.pem" -out "$WORK/certs/fullchain.pem" >/dev/null 2>&1 \
  || fail "temporary certificate generation failed"

python3 "$HERE/test-import-template-runtime.py" "$WORK" \
  || fail "template parser/renderer validation failed"
"$WORK/mihomo" -t -d "$WORK" -f "$WORK/mihomo.yaml" \
  || fail "repository Mihomo template failed real mihomo -t"

"$WORK/mosdns" start -d "$WORK" >"$WORK/mosdns.out" 2>&1 & PID=$!
for _ in $(seq 1 30); do
  kill -0 "$PID" 2>/dev/null || { cat "$WORK/mosdns.out" >&2; fail "mosdns exited during isolation window"; }
  sleep 0.1
done
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""
echo "[OK] import templates pass real Mihomo and isolated MosDNS runtime checks"
