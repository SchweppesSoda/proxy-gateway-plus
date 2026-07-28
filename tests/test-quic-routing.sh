#!/usr/bin/env bash
# Adversarial ownership/idempotency/rollback tests for native QUIC routing.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
RULES="$WORK/rules"; ROUTES="$WORK/routes"; STATE="$WORK/quic.state"
mkdir -p "$ROUTES"; : >"$RULES"

cat >"$WORK/ip" <<'FAKEIP'
#!/usr/bin/env bash
set -uo pipefail
rules="${FAKE_RULES:?}"; routes="${FAKE_ROUTES:?}"
[[ "${1:-}" == -4 ]] && shift
kind="${1:-}"; op="${2:-}"; shift 2 || true
if [[ "$kind" == rule && "$op" == show ]]; then
  [[ "${FAIL_RULE_SHOW:-0}" != 1 ]] || exit 44
  cat "$rules"; exit 0
fi
if [[ "$kind" == route && "$op" == show ]]; then
  [[ "${1:-}" == table ]] || exit 2
  if [[ "${FAIL_ROUTE_SHOW:-0}" == 1 ]]; then
    echo "RTNETLINK answers: Operation not permitted" >&2; exit 2
  fi
  if [[ "${MISSING_ROUTE_TABLE:-}" == "$2" && ! -e "$routes/$2" ]]; then
    echo "Error: ipv4: FIB table does not exist." >&2
    [[ "${MISSING_ROUTE_STYLE:-one}" != two ]] || echo "Dump terminated" >&2
    exit 2
  fi
  cat "$routes/$2" 2>/dev/null || true; exit 0
fi
if [[ "$kind" == rule && ( "$op" == add || "$op" == del ) ]]; then
  priority="" mark="" table=""
  while (($#)); do
    case "$1" in
      priority) priority="$2"; shift 2;;
      fwmark) mark="$2"; shift 2;;
      lookup) table="$2"; shift 2;;
      *) shift;;
    esac
  done
  line="$priority: from all fwmark $mark lookup $table"
  if [[ "$op" == add ]]; then
    [[ "${FAIL_RULE_PRIORITY:-}" != "$priority" ]] || exit 42
    grep -Fqx "$line" "$rules" 2>/dev/null || printf '%s\n' "$line" >>"$rules"
  else
    tmp="$rules.tmp"; grep -Fvx "$line" "$rules" >"$tmp" || true; mv "$tmp" "$rules"
  fi
  exit 0
fi
if [[ "$kind" == route && ( "$op" == replace || "$op" == del ) ]]; then
  table=""
  while (($#)); do
    case "$1" in table) table="$2"; shift 2;; *) shift;; esac
  done
  [[ -n "$table" ]] || exit 2
  if [[ "$op" == replace ]]; then
    [[ "${FAIL_ROUTE_TABLE:-}" != "$table" ]] || exit 43
    printf 'local default dev lo\n' >"$routes/$table"
  else
    rm -f "$routes/$table"
  fi
  exit 0
fi
exit 2
FAKEIP
chmod +x "$WORK/ip"

profile(){
  cat >"$WORK/profile.env" <<EOF
PDG_QUIC_MODE=${1:-tproxy}
PDG_QUIC_MARK=${2:-0x504447}
PDG_QUIC_MARK_MASK=${5:-0xffffffff}
PDG_QUIC_ROUTE_TABLE=${3:-7895}
PDG_QUIC_RULE_PRIORITY=${4:-17895}
EOF
}
q(){
  FAKE_RULES="$RULES" FAKE_ROUTES="$ROUTES" \
  PDG_IP_BIN="$WORK/ip" PDG_PROFILE="$WORK/profile.env" \
  PDG_QUIC_STATE="$STATE" PDG_PROFILE_TOOL="$ROOT/deploy/bot/pdgprofile.py" \
  FAIL_ROUTE_TABLE="${FAIL_ROUTE_TABLE:-}" FAIL_RULE_PRIORITY="${FAIL_RULE_PRIORITY:-}" \
  MISSING_ROUTE_TABLE="${MISSING_ROUTE_TABLE:-}" \
  MISSING_ROUTE_STYLE="${MISSING_ROUTE_STYLE:-one}" \
  FAIL_RULE_SHOW="${FAIL_RULE_SHOW:-0}" \
  FAIL_ROUTE_SHOW="${FAIL_ROUTE_SHOW:-0}" \
  bash "$ROOT/deploy/firewall/pdg-quic-routing.sh" "$@"
}
count_rule(){ grep -c '^' "$RULES" 2>/dev/null || true; }
fail(){ echo "[FAIL] $*" >&2; exit 1; }

# First apply is transactional when route creation fails after rule add.
profile
FAIL_ROUTE_TABLE=7895 q apply >/dev/null 2>&1 \
  && fail "first apply route failure accepted"
[[ ! -s "$RULES" && ! -e "$ROUTES/7895" && ! -e "$STATE" ]] \
  || fail "first apply leaked rule/route/state"

# Clean first apply, exact status, and repeat apply are idempotent.
profile
MISSING_ROUTE_TABLE=7895 q apply >/dev/null || fail "clean apply with absent FIB table"
q status | grep -q '^tproxy ' || fail "trusted exact status"
q apply >/dev/null || fail "repeat apply"
[[ "$(count_rule)" == 1 && "$(cat "$ROUTES/7895")" == "local default dev lo" ]] \
  || fail "idempotency"

# Exact trusted removal and read-only cleanup proof.
q remove >/dev/null || fail "trusted remove"
[[ ! -e "$STATE" && ! -s "$RULES" && ! -e "$ROUTES/7895" ]] \
  || fail "trusted tuple not removed exactly"
q cleanup-status >/dev/null || fail "clean proof"
profile tproxy 0x504450 7898 17898
MISSING_ROUTE_TABLE=7898 MISSING_ROUTE_STYLE=two q preflight >/dev/null \
  || fail "two-line absent FIB diagnostic"
FAIL_ROUTE_SHOW=1 q preflight >/dev/null 2>&1 \
  && fail "non-FIB route read failure accepted"
profile

# Public preflight rejects any foreign use of our route table and every
# mathematically overlapping fwmark match-set, regardless of priority/table.
printf '20000: from all fwmark 0x111111/0xffffffff lookup 7895\n' >"$RULES"
q preflight >/dev/null 2>&1 && fail "different mark on target table accepted"
printf '20000: from all fwmark 0x4000/0xf000 lookup 100\n' >"$RULES"
profile tproxy 0x4400 7895 17895 0xff00
q preflight >/dev/null 2>&1 && fail "wide-mask overlap on foreign table accepted"
printf '20000: from all fwmark 0x4500/0xff00 lookup 100\n' >"$RULES"
q preflight >/dev/null || fail "unrelated disjoint foreign rule rejected"
printf '20000: from all fwmark not-a-mark lookup 100\n' >"$RULES"
q preflight >/dev/null 2>&1 && fail "unparseable fwmark rule accepted"
printf '17895: from 192.0.2.0/24 fwmark 0x504447/0xffffffff lookup 7895\n' >"$RULES"
q preflight >/dev/null 2>&1 && fail "extra source selector treated as exact"
printf '17895: not from all fwmark 0x504447/0xffffffff lookup 7895\n' >"$RULES"
q preflight >/dev/null 2>&1 && fail "not selector treated as exact"
printf '20000: from all fwmark 0x4500/0xff00 lookup pdg_target\n' >"$RULES"
q preflight >/dev/null 2>&1 && fail "unresolved rt_tables name accepted"
: >"$RULES"
printf 'local default dev lo scope host metric 1\n' >"$ROUTES/7895"
q preflight >/dev/null 2>&1 && fail "route with extra semantic fields treated as exact"
rm -f "$ROUTES/7895"
: >"$RULES"; profile

# Shape equality without state is foreign: never adopt and never delete.
printf '17895: from all fwmark 0x504447/0xffffffff lookup 7895\n' >"$RULES"
printf 'local default dev lo\n' >"$ROUTES/7895"
q apply >/dev/null 2>&1 && fail "adopted foreign exact tuple"
q remove >/dev/null || fail "missing-state remove should be a no-op"
[[ -s "$RULES" && -e "$ROUTES/7895" ]] || fail "deleted foreign exact tuple"
q cleanup-status >/dev/null 2>&1 && fail "false clean with unowned exact tuple"

# Corrupt state is loud and cannot authorize cleanup.
printf 'MARK=0x504447\nBROKEN=yes\n' >"$STATE"
q remove >/dev/null 2>&1 && fail "corrupt state accepted"
[[ -s "$RULES" && -e "$ROUTES/7895" ]] || fail "corrupt state deleted tuple"
rm -f "$STATE" "$ROUTES/7895"; : >"$RULES"

# Status requires state/profile equality plus both exact kernel objects.
q apply >/dev/null || fail "setup for status adversary"
profile tproxy 0x504448 7896 17896
q status >/dev/null 2>&1 && fail "state/profile mismatch green"
profile
: >"$RULES"
q status >/dev/null 2>&1 && fail "missing exact rule green"
q remove >/dev/null || fail "cleanup partial trusted tuple"

# Old -> new preflight conflict leaves old coverage and state intact.
profile tproxy 0x504447 7895 17895
q apply >/dev/null || fail "old tuple setup"
profile tproxy 0x504448 7896 17896
printf '17896: from all lookup 100\n' >>"$RULES"
q apply >/dev/null 2>&1 && fail "migration ignored new conflict"
grep -q '^17895: .*lookup 7895$' "$RULES" || fail "old rule lost on preflight"
[[ -e "$ROUTES/7895" ]] || fail "old route lost on preflight"
grep -q '^TABLE=7895$' "$STATE" || fail "old state changed on preflight"
grep -v '^17896:' "$RULES" >"$RULES.tmp" || true; mv "$RULES.tmp" "$RULES"

# Failed new setup rolls back new objects and restores exact old tuple/state.
FAIL_ROUTE_TABLE=7896 q apply >/dev/null 2>&1 \
  && fail "simulated new route failure accepted"
grep -q '^17895: .*lookup 7895$' "$RULES" || fail "old rule not restored"
! grep -q '^17896:' "$RULES" || fail "new rule leaked after rollback"
[[ -e "$ROUTES/7895" && ! -e "$ROUTES/7896" ]] || fail "route rollback"
grep -q '^TABLE=7895$' "$STATE" || fail "state rollback"

# Clean migration commits exactly one new tuple.
q apply >/dev/null || fail "clean tuple migration"
q status >/dev/null || fail "new tuple status"
grep -q '^17896: .*lookup 7896$' "$RULES" || fail "new rule absent"
! grep -q '^17895:' "$RULES" || fail "old rule remained"
[[ -e "$ROUTES/7896" && ! -e "$ROUTES/7895" ]] || fail "new route commit"

# Transaction caller recovery after apply succeeds but its commit/status gate
# fails: restore the captured trusted before-state, not only old nft.
cp "$STATE" "$WORK/state.before-status-fail"
profile tproxy 0x504449 7897 17897
q apply >/dev/null || fail "third tuple apply"
FAIL_RULE_SHOW=1 q status >/dev/null 2>&1 \
  && fail "injected status failure did not fire"
q rollback-state "$WORK/state.before-status-fail" >/dev/null \
  || fail "trusted state rollback after status failure"
profile tproxy 0x504448 7896 17896
q status >/dev/null || fail "restored tuple status"
grep -q '^17896: .*lookup 7896$' "$RULES" || fail "restored rule absent"
! grep -q '^17897:' "$RULES" || fail "post-status new rule leaked"

# Mark-only migration safely reuses the old trusted priority/shared table.
profile tproxy 0x504449 7896 17896
q preflight >/dev/null || fail "mark-only public preflight"
q apply >/dev/null || fail "mark-only apply"
q status >/dev/null || fail "mark-only status"
grep -q '^17896: .*fwmark 0x504449/0xffffffff lookup 7896$' "$RULES" \
  || fail "new mark rule absent"
! grep -q 'fwmark 0x504448/' "$RULES" || fail "old mark rule orphaned"

# Partial table/priority overlap is explicitly rejected; all-change migration
# was exercised above and remains supported.
profile tproxy 0x504450 7896 17900
q preflight >/dev/null 2>&1 && fail "priority-only overlap accepted"
profile tproxy 0x504450 7900 17896
q preflight >/dev/null 2>&1 && fail "table-only overlap accepted"

echo "[OK] QUIC routing ownership/idempotency/migration rollback"
