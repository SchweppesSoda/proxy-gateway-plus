#!/usr/bin/env bash
# 从维护者本机通过私有 SSH alias 部署最新 PDG Release。
# 真实 IP、端口和 IdentityFile 只保存在 ~/.ssh/config，不进入仓库。
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/release-tags.sh
source "$ROOT/lib/release-tags.sh"
DEFAULT_TARGET="kfc-pdg"
EXPECTED_REPOSITORY="SchweppesSoda/proxy-gateway-plus"
CONNECT_TIMEOUT="${PDG_SSH_CONNECT_TIMEOUT:-15}"
EXPECTED_VERSION="${PDG_EXPECTED_VERSION:-}"
TARGETS=()

usage(){
  cat <<'EOF'
用法: bash tools/deploy-release.sh [--expected vX.Y.Z] [SSH_ALIAS ...]

默认 SSH alias: kfc-pdg
也可用 PDG_EXPECTED_VERSION 和 PDG_SSH_CONNECT_TIMEOUT 环境变量。

流程: PDG 身份预检 → origin 精确版本预检 → update --dry-run → update → 版本/服务核验 → doctor --deep
EOF
}

fail(){
  echo "[FAIL] $*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --expected)
      (($# >= 2)) || fail "--expected 缺少版本号"
      EXPECTED_VERSION="$2"
      shift 2
      ;;
    --)
      shift
      TARGETS+=("$@")
      break
      ;;
    -*)
      fail "未知参数: $1"
      ;;
    *)
      TARGETS+=("$1")
      shift
      ;;
  esac
done

[[ "$CONNECT_TIMEOUT" =~ ^[1-9][0-9]*$ ]] \
  || fail "PDG_SSH_CONNECT_TIMEOUT 必须是正整数"
if [[ -n "$EXPECTED_VERSION" ]]; then
  pdg_release_semver_valid "$EXPECTED_VERSION" \
    || fail "期望版本必须是 vX.Y.Z: $EXPECTED_VERSION"
fi

((${#TARGETS[@]})) || TARGETS=("$DEFAULT_TARGET")
command -v ssh >/dev/null 2>&1 || fail "找不到 ssh"
SSH=(ssh -o BatchMode=yes -o "ConnectTimeout=${CONNECT_TIMEOUT}")

for target in "${TARGETS[@]}"; do
  [[ "$target" =~ ^[A-Za-z0-9._-]+$ ]] \
    || fail "SSH alias 只允许字母、数字、点、下划线和连字符: $target"

  echo "==> [$target] 检查 SSH 配置与 PDG 身份"
  "${SSH[@]}" -G "$target" >/dev/null \
    || fail "[$target] SSH 配置无法解析"
  if ! repository_origin="$("${SSH[@]}" "$target" \
      "test -x /usr/local/bin/pdg && test -d /opt/privdns-gateway && git -C /opt/privdns-gateway remote get-url origin")"; then
    fail "[$target] 不是可管理的 PDG 实例；拒绝部署"
  fi
  repository_origin="${repository_origin//$'\r'/}"
  case "$repository_origin" in
    "https://github.com/${EXPECTED_REPOSITORY}"|\
    "https://github.com/${EXPECTED_REPOSITORY}.git"|\
    "git@github.com:${EXPECTED_REPOSITORY}"|\
    "git@github.com:${EXPECTED_REPOSITORY}.git")
      ;;
    *)
      fail "[$target] PDG 仓库 origin 不符合预期；拒绝部署"
      ;;
  esac

  update_args=()
  release_mode="latest"
  trusted_commit=""
  if [[ -n "$EXPECTED_VERSION" ]]; then
    echo "==> [$target] 核验 origin 精确发布 $EXPECTED_VERSION"
    # This preflight also protects the first upgrade from a legacy pdg whose
    # parser predates --target.  It makes no system/config changes: only Git
    # remote refs/tags are refreshed before the old updater can select one.
    release_preflight="set -eu
repo=/opt/privdns-gateway
expected=$EXPECTED_VERSION
ns=refs/pdg-deploy-target/$EXPECTED_VERSION
git -C \"\$repo\" fetch -q --force --prune origin \"+refs/heads/main:refs/remotes/origin/main\" \"+refs/tags/\$expected:\$ns\"
commit=\$(git -C \"\$repo\" rev-parse --verify \"\$ns^{commit}\")
git -C \"\$repo\" merge-base --is-ancestor \"\$commit\" refs/remotes/origin/main
mode=target
if ! grep -Fq -- '--target)' /usr/local/bin/pdg; then
  git -C \"\$repo\" fetch -q --force --tags origin main
  latest=\$(git -C \"\$repo\" tag -l 'v*' --sort=-v:refname | head -1)
  test \"\$latest\" = \"\$expected\"
  legacy_commit=\$(git -C \"\$repo\" rev-parse --verify \"refs/tags/\$expected^{commit}\")
  test \"\$legacy_commit\" = \"\$commit\"
  mode=legacy
fi
printf '%s\\t%s\\t%s\\n' \"\$mode\" \"\$expected\" \"\$commit\""
    if ! release_result="$("${SSH[@]}" "$target" "$release_preflight")"; then
      fail "[$target] origin 未公布可达的精确版本，或 legacy 本地 tag 集不安全"
    fi
    release_result="${release_result//$'\r'/}"
    [[ "$release_result" != *$'\n'* ]] \
      || fail "[$target] origin 精确版本预检返回了多行结果"
    IFS=$'\t' read -r release_mode release_version trusted_commit release_extra \
      <<<"$release_result"
    [[ "$release_result" == "$release_mode"$'\t'"$release_version"$'\t'"$trusted_commit" \
       && -z "${release_extra:-}" \
       && "$release_version" == "$EXPECTED_VERSION" \
       && "$trusted_commit" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] \
      || fail "[$target] origin 精确版本预检返回格式无效"
    case "$release_mode" in
      target) update_args=(--target "$EXPECTED_VERSION");;
      legacy) update_args=();;
      *) fail "[$target] origin 精确版本预检返回未知 updater 模式";;
    esac
  fi

  echo "==> [$target] 更新预检"
  remote_dry_run="/usr/local/bin/pdg update --dry-run"
  remote_update="/usr/local/bin/pdg update"
  if ((${#update_args[@]})); then
    remote_dry_run+=" --target ${update_args[1]}"
    remote_update+=" --target ${update_args[1]}"
  fi
  "${SSH[@]}" "$target" "$remote_dry_run" \
    || fail "[$target] 更新预检失败"

  echo "==> [$target] 执行事务化更新"
  "${SSH[@]}" "$target" "$remote_update" \
    || fail "[$target] 更新失败；请检查远端回滚结果"

  echo "==> [$target] 核验发布版本与 clean worktree"
  if [[ -n "$EXPECTED_VERSION" ]]; then
    release_verify="set -eu
repo=/opt/privdns-gateway
expected=$EXPECTED_VERSION
trusted=$trusted_commit
worktree_status=\$(git -C \"\$repo\" status --porcelain=v1 --untracked-files=all)
test -z \"\$worktree_status\"
head=\$(git -C \"\$repo\" rev-parse --verify HEAD^{commit})
origin_commit=\$(git -C \"\$repo\" rev-parse --verify \"refs/pdg-deploy-target/\$expected^{commit}\")
tag_commit=\$(git -C \"\$repo\" rev-parse --verify \"refs/tags/\$expected^{commit}\")
test \"\$head\" = \"\$trusted\"
test \"\$origin_commit\" = \"\$trusted\"
test \"\$tag_commit\" = \"\$trusted\"
tags=\$(git -C \"\$repo\" tag --points-at HEAD)
test \"\$tags\" = \"\$expected\"
printf '%s\\t%s\\n' \"\$expected\" \"\$head\""
  else
    release_verify='set -eu
repo=/opt/privdns-gateway
worktree_status=$(git -C "$repo" status --porcelain=v1 --untracked-files=all)
test -z "$worktree_status"
selected=$(bash "$repo/lib/release-tags.sh" select "$repo")
tag=$(printf "%s\n" "$selected" | cut -f1)
trusted=$(printf "%s\n" "$selected" | cut -f2)
head=$(git -C "$repo" rev-parse --verify HEAD^{commit})
tag_commit=$(git -C "$repo" rev-parse --verify "refs/tags/$tag^{commit}")
test "$head" = "$trusted"
test "$tag_commit" = "$trusted"
tags=$(git -C "$repo" tag --points-at HEAD)
test "$tags" = "$tag"
printf "%s\t%s\n" "$tag" "$head"'
  fi
  if ! installed_result="$("${SSH[@]}" "$target" "$release_verify")"; then
    fail "[$target] 更新后不是 origin 对应的唯一精确 clean release"
  fi
  installed_result="${installed_result//$'\r'/}"
  [[ "$installed_result" != *$'\n'* ]] \
    || fail "[$target] 更新后版本校验返回了多行结果"
  IFS=$'\t' read -r installed_version installed_commit installed_extra \
    <<<"$installed_result"
  [[ "$installed_result" == "$installed_version"$'\t'"$installed_commit" \
     && -z "${installed_extra:-}" \
     && "$installed_commit" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] \
    || fail "[$target] 更新后版本校验返回格式无效"
  pdg_release_semver_valid "$installed_version" \
    || fail "[$target] 更新后版本不是严格 SemVer tag: $installed_version"
  if [[ -n "$EXPECTED_VERSION" && "$installed_commit" != "$trusted_commit" ]]; then
    fail "[$target] 更新后 commit 与 origin 预检 commit 不一致"
  fi
  if [[ -n "$EXPECTED_VERSION" && "$installed_version" != "$EXPECTED_VERSION" ]]; then
    fail "[$target] 版本不符: 期望 $EXPECTED_VERSION，实际 $installed_version"
  fi

  echo "==> [$target] 核验核心服务"
  "${SSH[@]}" "$target" "systemctl is-active pdg-web pdg-bot mihomo mosdns" \
    || fail "[$target] 至少一个核心服务未运行"

  echo "==> [$target] 深度自检"
  "${SSH[@]}" "$target" "/usr/local/bin/pdg doctor --deep" \
    || fail "[$target] 深度自检失败"

  echo "[OK] [$target] 已部署 $installed_version"
done
