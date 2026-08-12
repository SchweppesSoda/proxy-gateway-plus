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
logged_remote="${remote//$'\n'/\\n}"
printf '%s|%s\n' "$target" "$logged_remote" >> "$PDG_TEST_SSH_LOG"

case "$remote" in
  "test -x /usr/local/bin/pdg && test -d /opt/privdns-gateway && git -C /opt/privdns-gateway remote get-url origin")
    [[ "${PDG_TEST_PREFLIGHT_FAIL:-0}" != 1 ]]
    echo "${PDG_TEST_ORIGIN:-https://github.com/SchweppesSoda/proxy-gateway-plus.git}"
    ;;
  *"status --porcelain=v1 --untracked-files=all"*)
    [[ -z "${PDG_TEST_VERIFY_FAIL:-}" ]]
    printf '%s\t%s\n' "${PDG_TEST_VERSION:-v9.9.9}" 1111111111111111111111111111111111111111
    ;;
  *"refs/pdg-deploy-target/"*)
    [[ "${PDG_TEST_TARGET_FAIL:-0}" != 1 ]]
    if [[ -n "${PDG_TEST_PREFLIGHT_OUTPUT:-}" ]]; then
      printf '%b' "$PDG_TEST_PREFLIGHT_OUTPUT"
    else
      : "${PDG_TEST_REMOTE_PDG:?}"
      if grep -Fq -- '--target)' "$PDG_TEST_REMOTE_PDG"; then
        mode=target
      else
        mode=legacy
      fi
      printf '%s\t%s\t%s\n' "$mode" v9.9.9 1111111111111111111111111111111111111111
    fi
    ;;
  "/usr/local/bin/pdg update --dry-run"|"/usr/local/bin/pdg update --dry-run --target "*)
    echo "当前: v9.9.8 最新发布: v9.9.9"
    ;;
  "/usr/local/bin/pdg update"|"/usr/local/bin/pdg update --target "*)
    echo "已切到发布 v9.9.9"
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
LEGACY_PDG="$ROOT/tests/fixtures/pdg-v1.6.4.fixture"
LEGACY_NOTE="$ROOT/tests/fixtures/pdg-v1.6.4.README.md"
LEGACY_REL="tests/fixtures/pdg-v1.6.4.fixture"
[[ -f "$LEGACY_PDG" && ! -L "$LEGACY_PDG" ]] \
  || fail "v1.6.4 parser fixture 必须是普通文件"
[[ "$(uname -s)" != Linux || ! -x "$LEGACY_PDG" ]] \
  || fail "v1.6.4 parser fixture 在 Linux checkout 中不得可执行"
LEGACY_ATTRS="$(git -C "$ROOT" check-attr text eol -- "$LEGACY_REL")"
grep -Fqx "$LEGACY_REL: text: set" <<<"$LEGACY_ATTRS" \
  && grep -Fqx "$LEGACY_REL: eol: lf" <<<"$LEGACY_ATTRS" \
  || fail "v1.6.4 parser fixture 缺少精确 LF checkout 契约"
[[ "$(wc -c < "$LEGACY_PDG" | tr -d ' ')" == 253360 ]] \
  || fail "v1.6.4 parser fixture 字节数漂移"
[[ "$(git hash-object --no-filters "$LEGACY_PDG")" == \
   35e99a58707e448b206189162ca0b7446a09c204 ]] \
  || fail "v1.6.4 parser fixture Git blob 漂移"
[[ "$(sha256sum "$LEGACY_PDG" | awk '{print $1}')" == \
   0068d5bc8e9f3b1e59ab5cc6791626a7d410461b1cd8b04ec1ecaed68575042e ]] \
  || fail "v1.6.4 parser fixture SHA-256 漂移"
grep -Fqx -- '- Tag object: `2ab5a7dfcd8b53c3c0960bd23553f39a582ca258`' "$LEGACY_NOTE" \
  && grep -Fqx -- '- Peeled commit: `e070a9f5f0a463170e73f74c4505eba97300137d`' "$LEGACY_NOTE" \
  && grep -Fqx -- '- Git blob: `35e99a58707e448b206189162ca0b7446a09c204`' "$LEGACY_NOTE" \
  || fail "v1.6.4 parser fixture 来源契约漂移"
grep -Fq 'if [[ "${1:-}" == "--dry-run" ]]' "$LEGACY_PDG" \
  || fail "v1.6.4 parser fixture 不再是单参数 dry-run parser"
grep -Fq 'update|up)     shift || true; cmd_update "${1:-}";;' "$LEGACY_PDG" \
  || fail "v1.6.4 parser fixture dispatcher 形态异常"
! grep -Fq -- '--target)' "$LEGACY_PDG" \
  || fail "v1.6.4 parser fixture 意外支持 --target"
export PDG_TEST_REMOTE_PDG="$ROOT/deploy/bot/pdg.sh"

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
[[ "${#calls[@]}" == 8 ]] || fail "成功流程 SSH 调用数错误: ${#calls[@]}"
[[ "${calls[0]}" == "kfc-pdg|CONFIG" ]] || fail "未先检查默认 SSH alias"
[[ "${calls[1]}" == "kfc-pdg|test -x /usr/local/bin/pdg && test -d /opt/privdns-gateway && git -C /opt/privdns-gateway remote get-url origin" ]] \
  || fail "未在更新前核验 PDG 身份"
[[ "${calls[2]}" == *"refs/pdg-deploy-target/v9.9.9"* ]] \
  || fail "未在写入前核验 origin 精确 target"
[[ "${calls[3]}" == "kfc-pdg|/usr/local/bin/pdg update --dry-run --target v9.9.9" ]] \
  || fail "未对精确 target 执行更新预检"
[[ "${calls[4]}" == "kfc-pdg|/usr/local/bin/pdg update --target v9.9.9" ]] \
  || fail "未在预检后正式更新精确 target"
[[ "${calls[5]}" == *"status --porcelain=v1 --untracked-files=all"* \
   && "${calls[5]}" == *"refs/pdg-deploy-target/\$expected^{commit}"* \
   && "${calls[5]}" == *"refs/tags/\$expected^{commit}"* \
   && "${calls[5]}" == *"tag --points-at HEAD"* ]] \
  || fail "未核验 origin/tag/HEAD 同一、唯一 tag 与全量 clean worktree"
[[ "${calls[6]}" == "kfc-pdg|systemctl is-active pdg-web pdg-bot mihomo mosdns" ]] \
  || fail "未核验核心服务"
[[ "${calls[7]}" == "kfc-pdg|/usr/local/bin/pdg doctor --deep" ]] \
  || fail "未以深度自检收尾"
grep -q '\[OK\].*v9.9.9' "$OUT" || fail "成功输出缺版本"
pass "新 updater 按精确 target 安全顺序部署"

: > "$LOG"
PDG_TEST_REMOTE_PDG="$LEGACY_PDG" PATH="$WORK/bin:$PATH" PDG_TEST_VERSION=v9.9.9 \
  bash "$ROOT/tools/deploy-release.sh" --expected v9.9.9 > "$OUT"
mapfile -t calls < "$LOG"
[[ "${calls[3]}" == "kfc-pdg|/usr/local/bin/pdg update --dry-run" ]] \
  || fail "v1.6.4 legacy updater 预检被错误传入 --target"
[[ "${calls[4]}" == "kfc-pdg|/usr/local/bin/pdg update" ]] \
  || fail "v1.6.4 legacy updater 正式更新被错误传入 --target"
[[ "${calls[2]}" == *"legacy_commit="* \
   && "${calls[2]}" == *'test "$legacy_commit" = "$commit"'* ]] \
  || fail "legacy 预检未证明最高 tag peel 与 origin commit 一致"
pass "真实 v1.6.4 parser fixture 走无 target 的兼容命令序列"

: > "$LOG"
PATH="$WORK/bin:$PATH" PDG_TEST_VERSION=v9.9.9 \
  bash "$ROOT/tools/deploy-release.sh" > "$OUT"
mapfile -t calls < "$LOG"
[[ "${calls[2]}" == "kfc-pdg|/usr/local/bin/pdg update --dry-run" \
   && "${calls[3]}" == "kfc-pdg|/usr/local/bin/pdg update" ]] \
  || fail "无 expected 时未保持 latest 命令序列"
[[ "${calls[4]}" == *'lib/release-tags.sh" select'* \
   && "${calls[4]}" == *"tag --points-at HEAD"* ]] \
  || fail "无 expected 时未复核 origin-selected latest 与唯一本地 tag"
pass "无 expected 保持 origin latest 并做同等级最终验收"

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
if PATH="$WORK/bin:$PATH" PDG_TEST_TARGET_FAIL=1 \
    bash "$ROOT/tools/deploy-release.sh" --expected v9.9.9 >/dev/null 2>&1; then
  fail "origin 精确 target 不可验证时错误继续部署"
fi
! grep -q '|/usr/local/bin/pdg update' "$LOG" \
  || fail "精确 target 预检失败后仍执行了更新"
pass "origin 精确 target 在任何系统写入前 fail closed"

: > "$LOG"
if PATH="$WORK/bin:$PATH" \
    PDG_TEST_PREFLIGHT_OUTPUT=$'target\tv9.9.9\t1111111111111111111111111111111111111111\npoison\n' \
    bash "$ROOT/tools/deploy-release.sh" --expected v9.9.9 >/dev/null 2>&1; then
  fail "多行 capability 结果被错误接受"
fi
! grep -q '|/usr/local/bin/pdg update' "$LOG" \
  || fail "capability 输出格式无效后仍执行更新"
pass "preflight capability 只接受严格单行 mode/version/commit"

for verify_case in untracked modified co-tag; do
  : > "$LOG"
  if PATH="$WORK/bin:$PATH" PDG_TEST_VERIFY_FAIL="$verify_case" \
      bash "$ROOT/tools/deploy-release.sh" --expected v9.9.9 >/dev/null 2>&1; then
    fail "$verify_case 状态被错误验收为 clean exact release"
  fi
  grep -q 'status --porcelain=v1 --untracked-files=all' "$LOG" \
    || fail "$verify_case 未进入最终 clean/exact 验证"
  ! grep -q '|systemctl is-active pdg-web pdg-bot mihomo mosdns' "$LOG" \
    || fail "$verify_case 阻断后仍继续服务验收"
  ! grep -q '|/usr/local/bin/pdg doctor --deep' "$LOG" \
    || fail "$verify_case 阻断后仍继续 doctor"
done
pass "untracked/modified/co-tag 均在服务与 doctor 前阻断"

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
[[ -n "$(git -C "$FIXTURE" status --porcelain=v1 --untracked-files=all)" ]] \
  || fail "真实 Git porcelain 未发现 modified 文件"
git -C "$FIXTURE" restore release.txt
printf 'untracked\n' > "$FIXTURE/untracked.txt"
[[ -n "$(git -C "$FIXTURE" status --porcelain=v1 --untracked-files=all)" ]] \
  || fail "真实 Git porcelain 未发现 untracked 文件"
rm -f "$FIXTURE/untracked.txt"
git -C "$FIXTURE" tag poison-same-commit HEAD
[[ "$(git -C "$FIXTURE" tag --points-at HEAD | wc -l | tr -d ' ')" == 2 ]] \
  || fail "真实 Git fixture 未构造同 commit co-tag"
[[ "$(git -C "$FIXTURE" tag --points-at HEAD)" != v9.9.9 ]] \
  || fail "唯一 tag 验证未拒绝 co-tag"
pass "真实 Git clean/modified/untracked/co-tag 验收原语回归"
