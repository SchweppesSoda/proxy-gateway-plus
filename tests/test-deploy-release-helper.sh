#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT
mkdir -p "$WORK/bin"

fail(){ echo "[FAIL] $*" >&2; exit 1; }
pass(){ echo "[PASS] $*"; }

cat > "$WORK/bin/ssh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
: "${PDG_TEST_SSH_LOG:?}"

is_config=0
target=""
remote=""
while (($#)); do
  case "$1" in
    -o)
      shift 2
      ;;
    -G)
      is_config=1
      shift
      ;;
    *)
      target="$1"
      shift
      remote="${1:-}"
      break
      ;;
  esac
done

if [[ "$is_config" == 1 ]]; then
  printf '%s|CONFIG\n' "$target" >> "$PDG_TEST_SSH_LOG"
  exit 0
fi
printf '%s|%s\n' "$target" "$remote" >> "$PDG_TEST_SSH_LOG"

case "$remote" in
  "test -x /usr/local/bin/pdg && test -d /opt/privdns-gateway && git -C /opt/privdns-gateway remote get-url origin")
    [[ "${PDG_TEST_PREFLIGHT_FAIL:-0}" != 1 ]]
    echo "${PDG_TEST_ORIGIN:-https://github.com/SchweppesSoda/proxy-gateway-plus.git}"
    ;;
  "/usr/local/bin/pdg update --dry-run")
    echo "当前: v9.9.8 最新发布: v9.9.9"
    ;;
  "/usr/local/bin/pdg update")
    echo "已切到发布 v9.9.9"
    ;;
  "git -C /opt/privdns-gateway describe --tags --exact-match --dirty")
    echo "${PDG_TEST_VERSION:-v9.9.9}"
    ;;
  "systemctl is-active pdg-web pdg-bot mihomo mosdns")
    printf 'active\nactive\nactive\nactive\n'
    ;;
  "/usr/local/bin/pdg doctor --deep")
    echo "全部正常 (0 失败 / 0 警告)"
    ;;
  *)
    echo "unexpected remote command: $remote" >&2
    exit 64
    ;;
esac
MOCK
chmod +x "$WORK/bin/ssh"

LOG="$WORK/ssh.log"
OUT="$WORK/out.log"
export PDG_TEST_SSH_LOG="$LOG"

grep -Fq 'kfc-pdg' "$ROOT/AGENTS.md" \
  || fail "仓库级 agent 指令未固定生产 SSH alias"
grep -Fq 'tools/deploy-release.sh' "$ROOT/AGENTS.md" \
  || fail "仓库级 agent 指令未指定统一部署入口"
if grep -Eq '([0-9]{1,3}\.){3}[0-9]{1,3}' "$ROOT/AGENTS.md"; then
  fail "仓库级 agent 指令不应保存真实 IP inventory"
fi
pass "未来 agent 可发现统一入口且仓库不保存真实 IP"

: > "$LOG"
PATH="$WORK/bin:$PATH" PDG_TEST_VERSION=v9.9.9 \
  bash "$ROOT/tools/deploy-release.sh" --expected v9.9.9 > "$OUT"
mapfile -t calls < "$LOG"
[[ "${#calls[@]}" == 7 ]] || fail "成功流程 SSH 调用数错误: ${#calls[@]}"
[[ "${calls[0]}" == "kfc-pdg|CONFIG" ]] || fail "未先检查默认 SSH alias"
[[ "${calls[1]}" == "kfc-pdg|test -x /usr/local/bin/pdg && test -d /opt/privdns-gateway && git -C /opt/privdns-gateway remote get-url origin" ]] \
  || fail "未在更新前核验 PDG 身份"
[[ "${calls[2]}" == "kfc-pdg|/usr/local/bin/pdg update --dry-run" ]] \
  || fail "未先执行更新预检"
[[ "${calls[3]}" == "kfc-pdg|/usr/local/bin/pdg update" ]] \
  || fail "未在预检后正式更新"
[[ "${calls[4]}" == "kfc-pdg|git -C /opt/privdns-gateway describe --tags --exact-match --dirty" ]] \
  || fail "未核验精确发布 tag"
[[ "${calls[5]}" == "kfc-pdg|systemctl is-active pdg-web pdg-bot mihomo mosdns" ]] \
  || fail "未核验核心服务"
[[ "${calls[6]}" == "kfc-pdg|/usr/local/bin/pdg doctor --deep" ]] \
  || fail "未以深度自检收尾"
grep -q '\[OK\].*v9.9.9' "$OUT" || fail "成功输出缺版本"
pass "成功部署按安全顺序执行"

: > "$LOG"
if PATH="$WORK/bin:$PATH" bash "$ROOT/tools/deploy-release.sh" "bad target" >/dev/null 2>&1; then
  fail "含空格的 SSH alias 被错误接受"
fi
[[ ! -s "$LOG" ]] || fail "非法 alias 校验前不应调用 SSH"
pass "非法 SSH alias fail closed"

: > "$LOG"
if PATH="$WORK/bin:$PATH" PDG_TEST_PREFLIGHT_FAIL=1 \
    bash "$ROOT/tools/deploy-release.sh" >/dev/null 2>&1; then
  fail "非 PDG 目标通过了身份预检"
fi
! grep -q '|/usr/local/bin/pdg update' "$LOG" \
  || fail "身份预检失败后仍执行了更新"
pass "非 PDG 主机不会被误部署"

: > "$LOG"
if PATH="$WORK/bin:$PATH" PDG_TEST_ORIGIN=https://github.com/example/not-production.git \
    bash "$ROOT/tools/deploy-release.sh" >/dev/null 2>&1; then
  fail "错误仓库 origin 通过了身份预检"
fi
! grep -q '|/usr/local/bin/pdg update' "$LOG" \
  || fail "仓库 origin 不符后仍执行了更新"
pass "错误仓库 origin 不会被误部署"

: > "$LOG"
if PATH="$WORK/bin:$PATH" PDG_TEST_VERSION=v9.9.9 \
    bash "$ROOT/tools/deploy-release.sh" --expected v9.9.8 >/dev/null 2>&1; then
  fail "部署版本不符时错误返回成功"
fi
! grep -q '|/usr/local/bin/pdg doctor --deep' "$LOG" \
  || fail "版本不符后仍继续深度自检"
pass "版本不符立即失败"

FIXTURE="$WORK/git-fixture"
git init -q "$FIXTURE"
git -C "$FIXTURE" config user.name "PDG CI"
git -C "$FIXTURE" config user.email "pdg-ci@example.invalid"
git -C "$FIXTURE" config core.autocrlf false
printf 'release\n' > "$FIXTURE/release.txt"
git -C "$FIXTURE" add release.txt
git -C "$FIXTURE" commit -q -m release
git -C "$FIXTURE" tag v9.9.9
[[ "$(git -C "$FIXTURE" describe --tags --exact-match --dirty)" == v9.9.9 ]] \
  || fail "真实 Git 无法识别精确 clean tag"
printf 'dirty\n' >> "$FIXTURE/release.txt"
[[ "$(git -C "$FIXTURE" describe --tags --exact-match --dirty)" == v9.9.9-dirty ]] \
  || fail "真实 Git 未标识 dirty worktree"
pass "发布版本命令通过真实 Git clean/dirty 回归"
