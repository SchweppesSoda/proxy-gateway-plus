#!/usr/bin/env bash
# 首装 geosite bootstrap 回归：默认 live updater 不降级；bootstrap 必须有安装 marker、
# exact loaded/inactive，四类完整非空，并在事务锁内 guard；提交后再次断言 inactive。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; nfail=0
ok(){ echo "[OK]   $1"; pass=$((pass+1)); }
bad(){ echo "[FAIL] $1"; nfail=$((nfail+1)); }

SB="$WORK/root"
mkdir -p "$WORK/bin" "$SB/etc/privdns-gateway" "$SB/opt/pdg-bot" \
  "$SB/opt/privdns-gateway/deploy/bot"
: >"$SB/opt/pdg-bot/parse-geosite.py"
: >"$SB/opt/pdg-bot/pdgtx.py"

sed -e "s#/etc/privdns-gateway#$SB/etc/privdns-gateway#g" \
    -e "s#/opt/pdg-bot#$SB/opt/pdg-bot#g" \
    -e "s#/opt/privdns-gateway#$SB/opt/privdns-gateway#g" \
    "$ROOT/deploy/bot/update-rules.sh" >"$WORK/update-rules.sh"
chmod +x "$WORK/update-rules.sh"

cat >"$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then printf 'dat\n' >"$2"; exit 0; fi
  shift
done
exit 2
EOF
cat >"$WORK/bin/stat" <<'EOF'
#!/usr/bin/env bash
echo 0:600
EOF
cat >"$WORK/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
[[ "${MOCK_SYSTEMCTL_FAIL:-0}" == 1 ]] && exit 1
case "$*" in
  *LoadState*) echo "${MOCK_LOAD:-loaded}" ;;
  *ActiveState*)
    n=0; [[ -f "$MOCK_STATE_COUNT" ]] && n="$(cat "$MOCK_STATE_COUNT")"
    n=$((n+1)); echo "$n" >"$MOCK_STATE_COUNT"
    if [[ "$n" -gt 1 && -n "${MOCK_POST_ACTIVE+x}" ]]; then
      echo "$MOCK_POST_ACTIVE"
    elif [[ -n "${MOCK_ACTIVE+x}" ]]; then
      echo "$MOCK_ACTIVE"
    else
      echo inactive
    fi ;;
  *) exit 2 ;;
esac
EOF
cat >"$WORK/bin/python3" <<'EOF'
#!/usr/bin/env bash
tool="$1"; shift
if [[ "$(basename "$tool")" == parse-geosite.py ]]; then
  out="${@: -1}"; mkdir -p "$out"
  for f in geosite_cn geosite_geolocation-\!cn geosite_apple geosite_gfw; do
    [[ "${MOCK_EMPTY:-}" == "$f" ]] && : >"$out/$f.txt" || printf 'domain:test.example\n' >"$out/$f.txt"
  done
  exit 0
fi
cmd="$1"; shift
printf '%s %s\n' "$cmd" "$*" >>"$MOCK_TX_LOG"
case "$cmd" in new) echo tx-test;; apply) exit "${MOCK_APPLY_RC:-0}";; *) exit 0;; esac
EOF
chmod +x "$WORK/bin/"*

export PATH="$WORK/bin:/usr/bin:/bin"
export MOCK_TX_LOG="$WORK/tx.log" MOCK_STATE_COUNT="$WORK/state-count"
export RULE_SCRIPT="$WORK/update-rules.sh"

reset_case(){ : >"$MOCK_TX_LOG"; rm -f "$MOCK_STATE_COUNT"; unset MOCK_LOAD MOCK_ACTIVE MOCK_POST_ACTIVE MOCK_SYSTEMCTL_FAIL MOCK_EMPTY MOCK_APPLY_RC; }
cat >"$WORK/bootstrap-launcher.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$\$" >"$SB/etc/privdns-gateway/.installing-rules"
chmod 600 "$SB/etc/privdns-gateway/.installing-rules"
bash "\$RULE_SCRIPT" --bootstrap
EOF
chmod +x "$WORK/bootstrap-launcher.sh"
run_bootstrap(){ bash "$WORK/bootstrap-launcher.sh"; }

reset_case
bash "$WORK/update-rules.sh" >/dev/null 2>&1
rc=$?
[[ "$rc" == 0 ]] && grep -q 'new .*--mode normal' "$MOCK_TX_LOG" \
  && grep -q 'service .*restart:mosdns' "$MOCK_TX_LOG" \
  && ok "默认 live updater 保持 normal + restart" || bad "默认 updater 被弱化"

reset_case
boot_out="$(run_bootstrap 2>&1)"
rc=$?
[[ "$rc" == 0 ]] && grep -q 'new .*--mode repair' "$MOCK_TX_LOG" \
  && grep -q 'guard .*--expect inactive' "$MOCK_TX_LOG" \
  && ! grep -q '^service ' "$MOCK_TX_LOG" \
  && ok "首装 bootstrap 离线落盘且事务锁内 guard inactive" || bad "bootstrap 事务语义不符: $boot_out"

reset_case
rm -f "$SB/etc/privdns-gateway/.installing-rules"
bash "$WORK/update-rules.sh" --bootstrap >/dev/null 2>&1
[[ $? != 0 ]] && ok "无安装 marker 拒绝 bootstrap" || bad "无 marker 仍可 bootstrap"

for state in active failed unknown ""; do
  reset_case; export MOCK_ACTIVE="$state"
  run_bootstrap >/dev/null 2>&1
  [[ $? != 0 ]] && ok "ActiveState=${state:-empty} 拒绝" || bad "非 exact inactive 被接受: ${state:-empty}"
done

reset_case; export MOCK_EMPTY=geosite_cn
run_bootstrap >/dev/null 2>&1
[[ $? != 0 ]] && ! grep -q '^new ' "$MOCK_TX_LOG" \
  && ok "固定类别为空时在事务前拒绝" || bad "空类别仍提交"

reset_case; export MOCK_POST_ACTIVE=active
run_bootstrap >/dev/null 2>&1
[[ $? != 0 ]] && grep -q '^apply ' "$MOCK_TX_LOG" \
  && ok "提交后不再 inactive 则保守失败" || bad "缺少 apply 后状态断言"

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $nfail"
[[ "$nfail" == 0 ]]
