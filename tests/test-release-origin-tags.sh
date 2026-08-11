#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/release-tags.sh
source "$ROOT/lib/release-tags.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT

fail(){ echo "[FAIL] $*" >&2; exit 1; }
ok(){ echo "[OK]   $*"; }

git init -q --bare "$WORK/origin.git"
git init -q -b main "$WORK/source"
git -C "$WORK/source" config user.name "PDG Release Test"
git -C "$WORK/source" config user.email "pdg-release@example.invalid"
printf 'one\n' >"$WORK/source/file"
git -C "$WORK/source" add file
git -C "$WORK/source" commit -qm one
C1="$(git -C "$WORK/source" rev-parse HEAD)"
git -C "$WORK/source" tag -a v1.8.0 -m v1.8.0
printf 'two\n' >>"$WORK/source/file"
git -C "$WORK/source" commit -qam two
C2="$(git -C "$WORK/source" rev-parse HEAD)"
git -C "$WORK/source" tag v1.9.0-rc.2
git -C "$WORK/source" tag v1.9.0
git -C "$WORK/source" remote add origin "$WORK/origin.git"
git -C "$WORK/source" push -q origin main --tags
git -C "$WORK/origin.git" symbolic-ref HEAD refs/heads/main
git clone -q "$WORK/origin.git" "$WORK/client"

# Neither a high local poison tag nor a tag fetched from another remote is an
# origin release candidate.
git -C "$WORK/client" tag v99.0.0
git init -q --bare "$WORK/upstream.git"
git -C "$WORK/source" push -q "$WORK/upstream.git" "$C1:refs/heads/main"
git -C "$WORK/source" tag v98.0.0 "$C1"
git -C "$WORK/source" push -q "$WORK/upstream.git" refs/tags/v98.0.0
git -C "$WORK/client" remote add upstream "$WORK/upstream.git"
git -C "$WORK/client" fetch -q --tags upstream
pdg_origin_release_select "$WORK/client"
[[ "$PDG_RELEASE_TAG" == v1.9.0 && "$PDG_RELEASE_COMMIT" == "$C2" ]] \
  || fail "本地/上游 poison 影响 origin latest: $PDG_RELEASE_TAG $PDG_RELEASE_COMMIT"
ok "只选择 origin advertised release，忽略本地 v99 与分叉 upstream tag"

pdg_origin_release_select "$WORK/client" v1.8.0
[[ "$PDG_RELEASE_COMMIT" == "$C1" ]] || fail "annotated tag 未 peel 到 commit"
pdg_origin_release_select "$WORK/client" v1.9.0
[[ "$PDG_RELEASE_COMMIT" == "$C2" ]] || fail "lightweight tag 未解析到 commit"
ok "annotated/lightweight tag 均 peel 到 origin/main commit"

# A same-name local poison is ignored and materialization replaces it with the
# exact origin object only after selection.
git -C "$WORK/client" tag -f v1.9.0 "$C1" >/dev/null
pdg_origin_release_select "$WORK/client" v1.9.0
[[ "$PDG_RELEASE_COMMIT" == "$C2" ]] || fail "同名 local poison 覆盖了 origin namespace"
pdg_origin_release_materialize "$WORK/client"
[[ "$(git -C "$WORK/client" rev-parse v1.9.0^{commit})" == "$C2" ]] \
  || fail "materialize 未把本地 tag 固定为 origin object"
ok "同名 local poison 不参与选择，apply 时被精确 origin tag 替换"

[[ "$(pdg_release_semver_cmp v1.9.0 v1.9.0-rc.9)" == 1 \
   && "$(pdg_release_semver_cmp v2.0.0-alpha.2 v2.0.0-alpha.10)" == -1 \
   && "$(pdg_release_semver_cmp v2.0.0-alpha v2.0.0-alpha.1)" == -1 \
   && "$(pdg_release_semver_cmp v2.0.0-beta v2.0.0-alpha.99)" == 1 ]] \
  || fail "SemVer precedence 不正确"
if _pdg_release_semver_parse v1.0.0-01; then fail "非法前导零 prerelease 被接受"; fi
ok "SemVer stable/prerelease/numeric precedence 严格"

# The isolated namespace must be pruned when origin deletes a tag.
git -C "$WORK/source" tag v2.0.0
git -C "$WORK/source" push -q origin refs/tags/v2.0.0
pdg_origin_release_select "$WORK/client"
[[ "$PDG_RELEASE_TAG" == v2.0.0 ]] || fail "新增 origin tag 未被选择"
git -C "$WORK/source" push -q --delete origin v2.0.0
pdg_origin_release_select "$WORK/client"
[[ "$PDG_RELEASE_TAG" == v1.9.0 ]] || fail "已删远端 tag 仍被缓存选择"
! git -C "$WORK/client" show-ref --verify --quiet refs/pdg-origin-tags/v2.0.0 \
  || fail "隔离 namespace 未 prune 已删 tag"
ok "远端删除会 prune 隔离 tag namespace"

# The highest advertised SemVer being off main is a broken release and must
# fail closed, not silently fall back to an older version.
git -C "$WORK/source" checkout -qb side "$C1"
printf 'side\n' >"$WORK/source/side"
git -C "$WORK/source" add side
git -C "$WORK/source" commit -qm side
git -C "$WORK/source" tag v3.0.0
git -C "$WORK/source" push -q origin refs/tags/v3.0.0
if pdg_origin_release_select "$WORK/client" >/dev/null 2>&1; then
  fail "不在 origin/main 的最高 release tag 被接受"
fi
ok "origin tag commit 不可达 main 时 fail closed"
git -C "$WORK/source" push -q --delete origin v3.0.0

# A failed refresh must not reuse the previously fetched isolated refs.
git -C "$WORK/client" remote set-url origin "$WORK/missing-origin.git"
if pdg_origin_release_select "$WORK/client" v1.9.0 >/dev/null 2>&1; then
  fail "origin 离线时复用了旧 namespace"
fi
ok "origin 离线/获取失败时 fail closed"
