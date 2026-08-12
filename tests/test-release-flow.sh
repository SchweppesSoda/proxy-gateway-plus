#!/usr/bin/env bash
# Regression checks for the tag-only release/update path.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail(){ echo "[FAIL] $*" >&2; exit 1; }

grep -q 'pdg_checkout_latest_tag' "$ROOT/install.sh" \
  || fail "install.sh bootstrap must checkout the latest v* tag"
! grep -q 'git clone -q --depth 1 "$REPO_URL"' "$ROOT/install.sh" \
  || fail "install.sh must not seed /opt/privdns-gateway as a shallow main clone"
grep -q 'pdg_origin_release_select "$dir"' "$ROOT/install.sh" \
  || fail "install.sh must select only origin-advertised release tags"
grep -q 'checkout -q --detach "$target"' "$ROOT/install.sh" \
  || fail "install.sh must checkout the selected release tag before re-exec"

grep -q 'pdg_fetch_release_tags' "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg update must share a release-tag fetch helper"
grep -q 'pdg_origin_release_select "$dir" "$requested"' "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg update must use the origin-only release selector"
grep -q -- '--target)' "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg update must accept an exact release target"
! grep -q "tag -l 'v\*'" "$ROOT/deploy/bot/pdg.sh" \
  || fail "pdg update must not enumerate untrusted local tags"

grep -q '_select_origin_release' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must call the origin-only selector"
grep -q '"--target", target' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot apply must bind the confirmed exact target"
! grep -q '"tag", "-l", "v\*"' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot must not enumerate untrusted local tags"
grep -q 'mb.returncode == 0' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must distinguish merge-base success"
grep -q 'mb.returncode == 1' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must distinguish not-ancestor from git errors"
grep -q 'merge-base 判断失败' "$ROOT/deploy/bot/pdg-bot.py" \
  || fail "bot update check must report merge-base git errors instead of treating them as up-to-date"

! grep -q '1\.12\.9' "$ROOT/docs/INSTALL.md" \
  || fail "INSTALL.md must not mention stale sing-box 1.12.9"

for doc in \
  "$ROOT/README.md" \
  "$ROOT/docs/INSTALL.md" \
  "$ROOT/docs/QUICKSTART.md" \
  "$ROOT/docs/MOSDNS-PATCHED-BUILD.md" \
  "$ROOT/docs/forum-post.md"; do
  ! grep -q '派生仓库目前还没有兼容' "$doc" \
    || fail "$(basename "$doc") must not claim that no compatible Release exists"
  ! grep -Eq '^[[:space:]]*(sudo[[:space:]]+)?(env[[:space:]]+)?PDG_TAG_BOOTSTRAPPED=1([[:space:]\\]|$)' "$doc" \
    || fail "$(basename "$doc") must not instruct formal installs to bypass release tags"
done
