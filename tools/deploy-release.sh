#!/usr/bin/env bash
# 从维护者本机通过私有 SSH alias 部署最新 PDG Release。
# 真实 IP、端口和 IdentityFile 只保存在 ~/.ssh/config，不进入仓库。
set -Eeuo pipefail

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

流程: PDG 身份预检 → update --dry-run → update → 版本/服务核验 → doctor --deep
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
  [[ "$EXPECTED_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] \
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

  echo "==> [$target] 更新预检"
  "${SSH[@]}" "$target" "/usr/local/bin/pdg update --dry-run" \
    || fail "[$target] 更新预检失败"

  echo "==> [$target] 执行事务化更新"
  "${SSH[@]}" "$target" "/usr/local/bin/pdg update" \
    || fail "[$target] 更新失败；请检查远端回滚结果"

  echo "==> [$target] 核验发布版本"
  if ! installed_version="$("${SSH[@]}" "$target" \
      "git -C /opt/privdns-gateway describe --tags --exact-match --dirty")"; then
    fail "[$target] 更新后 HEAD 不在精确发布 tag"
  fi
  installed_version="${installed_version//$'\r'/}"
  [[ "$installed_version" == v* && "$installed_version" != *-dirty ]] \
    || fail "[$target] 更新后版本无效或仓库仍为 dirty: $installed_version"
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
