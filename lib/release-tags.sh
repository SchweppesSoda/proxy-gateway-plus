#!/usr/bin/env bash
# Select release tags only from the origin-advertised namespace.  Local tags
# are untrusted cache: they may have been fetched from another remote or left
# behind after a release was deleted.

PDG_RELEASE_TAG=""
PDG_RELEASE_COMMIT=""
PDG_RELEASE_OBJECT=""

_pdg_release_semver_parse(){
  local value="$1" core pre build ident
  [[ "$value" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]] \
    || return 1
  core="${value#v}"; build=""
  [[ "$core" == *+* ]] && { build="${core#*+}"; core="${core%%+*}"; }
  pre=""
  [[ "$core" == *-* ]] && { pre="${core#*-}"; core="${core%%-*}"; }
  if [[ -n "$pre" ]]; then
    local IFS=.
    for ident in $pre; do
      [[ "$ident" =~ ^[0-9]+$ && "$ident" != 0 && "$ident" == 0* ]] && return 1
    done
  fi
  PDG_SEMVER_CORE="$core"
  PDG_SEMVER_PRE="$pre"
  PDG_SEMVER_BUILD="$build"
}

pdg_release_semver_valid(){
  _pdg_release_semver_parse "$1"
}

_pdg_release_num_cmp(){
  local a="$1" b="$2"
  while [[ "$a" == 0* && "$a" != 0 ]]; do a="${a#0}"; done
  while [[ "$b" == 0* && "$b" != 0 ]]; do b="${b#0}"; done
  [[ -n "$a" ]] || a=0; [[ -n "$b" ]] || b=0
  # Equal-length normalized decimal strings are compared lexically so the
  # comparison remains exact beyond the shell's integer range.
  # shellcheck disable=SC2071
  if ((${#a} > ${#b})); then printf '1\n'
  elif ((${#a} < ${#b})); then printf '%s\n' '-1'
  elif [[ "$a" > "$b" ]]; then printf '1\n'
  elif [[ "$a" < "$b" ]]; then printf '%s\n' '-1'
  else printf '0\n'; fi
}

# Prints 1 when $1 has higher SemVer precedence, -1 when lower, 0 when equal.
pdg_release_semver_cmp(){
  local left="$1" right="$2" lc lp lb rc rp rb i cmp li ri LC_ALL=C
  _pdg_release_semver_parse "$left" || return 2
  lc="$PDG_SEMVER_CORE"; lp="$PDG_SEMVER_PRE"; lb="$PDG_SEMVER_BUILD"
  _pdg_release_semver_parse "$right" || return 2
  rc="$PDG_SEMVER_CORE"; rp="$PDG_SEMVER_PRE"; rb="$PDG_SEMVER_BUILD"
  local la=() ra=()
  IFS=. read -r -a la <<<"$lc"
  IFS=. read -r -a ra <<<"$rc"
  for i in 0 1 2; do
    cmp="$(_pdg_release_num_cmp "${la[$i]}" "${ra[$i]}")"
    [[ "$cmp" == 0 ]] || { printf '%s\n' "$cmp"; return 0; }
  done
  [[ -n "$lp" ]] || { [[ -z "$rp" ]] && printf '0\n' || printf '1\n'; return 0; }
  [[ -n "$rp" ]] || { printf '%s\n' '-1'; return 0; }
  local lparts=() rparts=()
  IFS=. read -r -a lparts <<<"$lp"
  IFS=. read -r -a rparts <<<"$rp"
  for ((i=0; i<${#lparts[@]} || i<${#rparts[@]}; i++)); do
    ((i < ${#lparts[@]})) || { printf '%s\n' '-1'; return 0; }
    ((i < ${#rparts[@]})) || { printf '1\n'; return 0; }
    li="${lparts[$i]}"; ri="${rparts[$i]}"
    if [[ "$li" =~ ^[0-9]+$ && "$ri" =~ ^[0-9]+$ ]]; then
      cmp="$(_pdg_release_num_cmp "$li" "$ri")"
      [[ "$cmp" == 0 ]] || { printf '%s\n' "$cmp"; return 0; }
    elif [[ "$li" =~ ^[0-9]+$ ]]; then
      printf '%s\n' '-1'; return 0
    elif [[ "$ri" =~ ^[0-9]+$ ]]; then
      printf '1\n'; return 0
    elif [[ "$li" > "$ri" ]]; then
      printf '1\n'; return 0
    elif [[ "$li" < "$ri" ]]; then
      printf '%s\n' '-1'; return 0
    fi
  done
  # Build metadata does not affect SemVer precedence.  Different tag names at
  # equal precedence are rejected by the selector as ambiguous.
  : "$lb" "$rb"
  printf '0\n'
}

pdg_origin_release_refresh(){
  local repo="$1" shallow
  [[ -d "$repo/.git" ]] || { echo "不是 Git 仓库: $repo" >&2; return 1; }
  git -C "$repo" remote get-url origin >/dev/null 2>&1 \
    || { echo "仓库缺少 origin" >&2; return 1; }
  git -C "$repo" fetch -q --force --prune origin \
    '+refs/heads/main:refs/remotes/origin/main' \
    '+refs/tags/v*:refs/pdg-origin-tags/v*' \
    || { echo "无法从 origin 获取 main/release tags" >&2; return 1; }
  shallow="$(git -C "$repo" rev-parse --is-shallow-repository 2>/dev/null)" || return 1
  if [[ "$shallow" == true ]]; then
    git -C "$repo" fetch -q --unshallow --force --prune origin \
      '+refs/heads/main:refs/remotes/origin/main' \
      '+refs/tags/v*:refs/pdg-origin-tags/v*' \
      || { echo "无法完整获取 origin release 历史" >&2; return 1; }
  fi
  git -C "$repo" rev-parse --verify "refs/remotes/origin/main^{commit}" >/dev/null 2>&1 \
    || { echo "origin/main 不可解析" >&2; return 1; }
}

pdg_origin_release_select(){
  local repo="$1" requested="${2:-}" ref tag best="" cmp object commit
  PDG_RELEASE_TAG=""; PDG_RELEASE_COMMIT=""; PDG_RELEASE_OBJECT=""
  pdg_origin_release_refresh "$repo" || return 1
  if [[ -n "$requested" ]]; then
    _pdg_release_semver_parse "$requested" \
      || { echo "目标版本不是严格 SemVer tag: $requested" >&2; return 1; }
    ref="refs/pdg-origin-tags/$requested"
    git -C "$repo" show-ref --verify --quiet "$ref" \
      || { echo "origin 未发布目标 tag: $requested" >&2; return 1; }
    best="$requested"
  else
    while IFS= read -r ref; do
      tag="${ref#refs/pdg-origin-tags/}"
      _pdg_release_semver_parse "$tag" || continue
      if [[ -z "$best" ]]; then best="$tag"; continue; fi
      cmp="$(pdg_release_semver_cmp "$tag" "$best")" || return 1
      if [[ "$cmp" == 1 ]]; then
        best="$tag"
      elif [[ "$cmp" == 0 && "$tag" != "$best" ]]; then
        echo "origin 存在 SemVer 优先级相同的歧义 tags: $best / $tag" >&2
        return 1
      fi
    done < <(git -C "$repo" for-each-ref --format='%(refname)' refs/pdg-origin-tags/)
    [[ -n "$best" ]] || { echo "origin 没有有效的 v* SemVer release tag" >&2; return 1; }
    ref="refs/pdg-origin-tags/$best"
  fi
  object="$(git -C "$repo" rev-parse --verify "$ref")" || return 1
  commit="$(git -C "$repo" rev-parse --verify "$ref^{commit}")" \
    || { echo "origin tag $best 无法 peel 到 commit" >&2; return 1; }
  git -C "$repo" merge-base --is-ancestor "$commit" refs/remotes/origin/main \
    || { echo "origin tag $best 不在 origin/main 历史上" >&2; return 1; }
  PDG_RELEASE_TAG="$best"; PDG_RELEASE_COMMIT="$commit"; PDG_RELEASE_OBJECT="$object"
}

pdg_origin_release_materialize(){
  local repo="$1" tag="${2:-$PDG_RELEASE_TAG}" object="${3:-$PDG_RELEASE_OBJECT}"
  [[ -n "$tag" && -n "$object" && "$tag" != */* ]] || return 1
  git -C "$repo" update-ref "refs/tags/$tag" "$object"
}

_pdg_release_cli(){
  local mode="${1:-}" repo="${2:-}" target="${3:-}"
  case "$mode" in
    select)
      pdg_origin_release_select "$repo" "$target" || return 1
      printf '%s\t%s\t%s\n' "$PDG_RELEASE_TAG" "$PDG_RELEASE_COMMIT" "$PDG_RELEASE_OBJECT"
      ;;
    *) echo "usage: release-tags.sh select <repo> [vX.Y.Z]" >&2; return 2;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -uo pipefail
  _pdg_release_cli "$@"
fi
