#!/usr/bin/env bash
# Reproducibly build the project MosDNS v5.3.4 no-session-ticket variant.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/versions.sh
source "$ROOT/lib/versions.sh"

ARCH=amd64
SOURCE=""
OUT="$ROOT/dist/mosdns"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) ARCH="${2:-}"; shift 2;;
    --source) SOURCE="${2:-}"; shift 2;;
    --out) OUT="${2:-}"; shift 2;;
    -h|--help)
      echo "usage: $0 [--arch amd64|arm64] [--source existing-mosdns-git] [--out directory]"
      exit 0;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
case "$ARCH" in amd64|arm64) ;; *) echo "--arch must be amd64 or arm64" >&2; exit 2;; esac

for cmd in git go sha256sum; do
  command -v "$cmd" >/dev/null || { echo "missing build dependency: $cmd" >&2; exit 1; }
done
[[ "$(go env GOVERSION)" == "go$MOSDNS_GO_VERSION" ]] || {
  echo "Go toolchain mismatch: expected go$MOSDNS_GO_VERSION, got $(go env GOVERSION)" >&2
  exit 1
}

PATCH="$ROOT/$MOSDNS_PATCH_FILE"
[[ -f "$PATCH" ]] || { echo "missing patch: $PATCH" >&2; exit 1; }
printf '%s  %s\n' "${PDG_SHA256[mosdns-patch]}" "$PATCH" | sha256sum -c -

WORK="$(mktemp -d)"
cleanup(){ rm -rf "$WORK"; }
trap cleanup EXIT
SRC="$WORK/src"
if [[ -n "$SOURCE" ]]; then
  [[ -d "$SOURCE/.git" ]] || { echo "--source must point to a git checkout" >&2; exit 1; }
  git clone -q --no-checkout "$SOURCE" "$SRC"
else
  git clone -q --no-checkout "$MOSDNS_UPSTREAM_REPO" "$SRC"
fi
git -C "$SRC" checkout -q --detach "$MOSDNS_UPSTREAM_COMMIT"
[[ "$(git -C "$SRC" rev-parse HEAD)" == "$MOSDNS_UPSTREAM_COMMIT" ]] || {
  echo "checked-out MosDNS commit mismatch" >&2
  exit 1
}
git -C "$SRC" diff --quiet && git -C "$SRC" diff --cached --quiet || {
  echo "upstream checkout is not clean" >&2
  exit 1
}
git -C "$SRC" apply --check "$PATCH"
git -C "$SRC" apply "$PATCH"
grep -Fq 'SessionTicketsDisabled: true' \
  "$SRC/plugin/server/tcp_server/tcp_server.go"

(
  cd "$SRC"
  go mod verify
  go test ./plugin/server/tcp_server
  export CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" GOFLAGS="-mod=readonly"
  [[ "$ARCH" == amd64 ]] && export GOAMD64=v1
  go build -buildvcs=false -trimpath \
    -ldflags="-s -w -buildid= -X main.version=$MOSDNS_BUILD_VERSION" \
    -o "$WORK/mosdns" .
)
case "$(uname -m):$ARCH" in
  x86_64:amd64|aarch64:arm64|arm64:arm64)
    [[ "$("$WORK/mosdns" version)" == "$MOSDNS_BUILD_VERSION" ]] || {
      echo "built MosDNS marker mismatch" >&2
      exit 1
    };;
  *)
    grep -aFq "$MOSDNS_BUILD_VERSION" "$WORK/mosdns" || {
      echo "cross-built MosDNS does not contain the target marker" >&2
      exit 1
    };;
esac

mkdir -p "$OUT"
ASSET="mosdns-${MOSDNS_VER}-${MOSDNS_PATCH_REV}-linux-${ARCH}"
install -m755 "$WORK/mosdns" "$OUT/$ASSET"
ARTIFACT_SHA="$(sha256sum "$OUT/$ASSET" | awk '{print $1}')"
PINNED_SHA="${PDG_SHA256[mosdns-pdg-$ARCH]:-}"
if [[ -n "$PINNED_SHA" && "$ARTIFACT_SHA" != "$PINNED_SHA" ]]; then
  rm -f "$OUT/$ASSET"
  echo "reproducible raw SHA mismatch: expected $PINNED_SHA, got $ARTIFACT_SHA" >&2
  exit 1
fi
cat >"$OUT/$ASSET.sha256" <<EOF
$ARTIFACT_SHA  $ASSET
EOF
cat >"$OUT/$ASSET.env" <<EOF
PDG_MOSDNS_ARTIFACT_SHA256=$ARTIFACT_SHA
EOF
cat >"$OUT/$ASSET.provenance.json" <<EOF
{
  "version": "$MOSDNS_BUILD_VERSION",
  "upstream_repository": "$MOSDNS_UPSTREAM_REPO",
  "upstream_commit": "$MOSDNS_UPSTREAM_COMMIT",
  "patch_file": "$MOSDNS_PATCH_FILE",
  "patch_sha256": "${PDG_SHA256[mosdns-patch]}",
  "go_version": "$MOSDNS_GO_VERSION",
  "goos": "linux",
  "goarch": "$ARCH",
  "cgo_enabled": false,
  "artifact": "$ASSET",
  "artifact_sha256": "$ARTIFACT_SHA",
  "binary_sha256": "$ARTIFACT_SHA"
}
EOF
printf 'built %s\nraw binary sha256: %s\n' "$OUT/$ASSET" "$ARTIFACT_SHA"
