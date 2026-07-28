#!/usr/bin/env bash
# Validated, same-directory atomic installation for /etc/nftables.conf.

pdg_nft_atomic_install(){
  local source="$1" target="${2:-/etc/nftables.conf}" nft_exe="${3:-}" dir tmp mode=644
  [[ -f "$source" && -s "$source" ]] || {
    echo "nft atomic install: source missing/empty: $source" >&2; return 1; }
  if [[ -z "$nft_exe" ]] && declare -F pdg_nft_bin >/dev/null 2>&1; then
    nft_exe="$(pdg_nft_bin || true)"
  fi
  [[ -n "$nft_exe" && -x "$nft_exe" ]] || {
    echo "nft atomic install: nft unavailable; refusing unvalidated write" >&2; return 1; }
  "$nft_exe" -c -f "$source" >/dev/null 2>&1 || {
    echo "nft atomic install: nft -c rejected candidate" >&2; return 1; }
  dir="$(dirname "$target")"
  tmp="$(mktemp "$dir/.nftables.conf.pdg.XXXXXX")" || return 1
  if [[ -e "$target" ]]; then
    mode="$(stat -c '%a' "$target" 2>/dev/null || echo 644)"
  fi
  if ! cp "$source" "$tmp" 2>/dev/null || ! cmp -s "$source" "$tmp" \
     || ! chmod "$mode" "$tmp" || ! mv -f "$tmp" "$target"; then
    rm -f "$tmp"
    echo "nft atomic install: candidate write/rename failed" >&2
    return 1
  fi
}
