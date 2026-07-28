#!/usr/bin/env bash
# Sourceable lifecycle helper for PDG native QUIC policy routing.
# Public: pdg_quic_preflight | pdg_quic_apply | pdg_quic_remove | pdg_quic_status

PDG_QUIC_PROFILE="${PDG_PROFILE:-/etc/privdns-gateway/profile.env}"
PDG_QUIC_STATE="${PDG_QUIC_STATE:-/etc/privdns-gateway/quic-routing.state}"
PDG_QUIC_PROFILE_TOOL="${PDG_PROFILE_TOOL:-/opt/pdg-bot/pdgprofile.py}"
PDG_QUIC_IP="${PDG_IP_BIN:-$(command -v ip 2>/dev/null || true)}"

_pdg_quic_load_profile(){
  local line
  [[ -f "$PDG_QUIC_PROFILE_TOOL" ]] || {
    echo "缺少严格 profile 解析器: $PDG_QUIC_PROFILE_TOOL" >&2; return 1; }
  line="$(python3 - "$PDG_QUIC_PROFILE_TOOL" "$PDG_QUIC_PROFILE" <<'PY'
import importlib.util, sys
from pathlib import Path
tool, profile = sys.argv[1:]
sys.path.insert(0, str(Path(tool).resolve().parent))
spec = importlib.util.spec_from_file_location("pdgprofile_quic_helper", tool)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
c = mod.resolve(profile, environ={})
print("|".join(map(str, (c["quic_mode"], c["mark_text"], c["mask_text"],
                         c["route_table"], c["rule_priority"]))))
PY
)" || return 1
  IFS='|' read -r PDG_Q_MODE PDG_Q_MARK PDG_Q_MASK PDG_Q_TABLE PDG_Q_PRIORITY <<<"$line"
  [[ "$PDG_Q_MODE" == tproxy || "$PDG_Q_MODE" == reject ]] || return 1
  [[ "$PDG_Q_MARK" =~ ^0x[0-9a-f]+$ && "$PDG_Q_MASK" =~ ^0x[0-9a-f]+$ ]] || return 1
  [[ "$PDG_Q_TABLE" =~ ^[0-9]+$ && "$PDG_Q_PRIORITY" =~ ^[0-9]+$ ]] || return 1
}

_pdg_quic_load_state(){
  [[ -f "$PDG_QUIC_STATE" ]] || return 1
  local key val seen="" line
  PDG_QS_MARK="" PDG_QS_MASK="" PDG_QS_TABLE="" PDG_QS_PRIORITY=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^(MARK|MASK|TABLE|PRIORITY)=([0-9a-fx]+)$ ]] || {
      echo "QUIC routing state 格式非法，拒绝猜测清理: $PDG_QUIC_STATE" >&2; return 2; }
    key="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
    [[ "|$seen|" != *"|$key|"* ]] || {
      echo "QUIC routing state 重复键: $key" >&2; return 2; }
    seen="${seen:+$seen|}$key"
    case "$key" in
      MARK) PDG_QS_MARK="$val";;
      MASK) PDG_QS_MASK="$val";;
      TABLE) PDG_QS_TABLE="$val";;
      PRIORITY) PDG_QS_PRIORITY="$val";;
    esac
  done < "$PDG_QUIC_STATE"
  [[ "$PDG_QS_MARK" =~ ^0x[0-9a-f]+$ \
     && "$PDG_QS_MASK" =~ ^0x[0-9a-f]+$ \
     && "$PDG_QS_TABLE" =~ ^[0-9]+$ \
     && "$PDG_QS_PRIORITY" =~ ^[0-9]+$ ]] || {
    echo "QUIC routing state 缺键/值非法，拒绝猜测清理" >&2; return 2; }
}

_pdg_quic_rule_exact(){
  local line="$1" priority="$2" mark="$3" mask="$4" table="$5"
  local line_priority mark_token line_table parsed rule_mark rule_mask
  local target_mark target_mask
  [[ "$line" =~ ^[[:space:]]*([0-9]+):[[:space:]]+from[[:space:]]+all[[:space:]]+fwmark[[:space:]]+([^[:space:]]+)[[:space:]]+(lookup|table)[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] \
    || return 1
  line_priority="${BASH_REMATCH[1]}"; mark_token="${BASH_REMATCH[2]}"
  line_table="${BASH_REMATCH[4]}"
  [[ "$line_priority" == "$priority" && "$line_table" == "$table" ]] \
    || return 1
  parsed="$(_pdg_quic_parse_mark_token "$mark_token")" || return 1
  IFS='|' read -r rule_mark rule_mask <<<"$parsed"
  target_mark="$(_pdg_quic_u32 "$mark")" || return 1
  target_mask="$(_pdg_quic_u32 "$mask")" || return 1
  (( rule_mark == target_mark && rule_mask == target_mask ))
}

_pdg_quic_route_exact(){
  # This is the complete output shape of:
  #   ip -4 route replace local 0.0.0.0/0 dev lo table TABLE
  # iproute2 normally appends "scope host"; the fake-ip regression omits it.
  [[ "$1" =~ ^local[[:space:]]+(default|0\.0\.0\.0/0)[[:space:]]+dev[[:space:]]+lo([[:space:]]+scope[[:space:]]+host)?[[:space:]]*$ ]]
}

_pdg_quic_u32(){
  local token="$1" digits value
  if [[ "$token" =~ ^0[xX]([0-9a-fA-F]{1,8})$ ]]; then
    digits="${BASH_REMATCH[1]}"; value=$((16#$digits))
  elif [[ "$token" =~ ^[0-9]{1,10}$ ]]; then
    value=$((10#$token))
  else
    return 1
  fi
  (( value >= 0 && value <= 4294967295 )) || return 1
  printf '%u\n' "$value"
}

_pdg_quic_parse_mark_token(){
  local token="$1" mark_token mask_token mark_value mask_value
  if [[ "$token" == */* ]]; then
    mark_token="${token%%/*}"; mask_token="${token#*/}"
    [[ -n "$mark_token" && -n "$mask_token" && "$mask_token" != */* ]] \
      || return 1
  else
    mark_token="$token"; mask_token=0xffffffff
  fi
  mark_value="$(_pdg_quic_u32 "$mark_token")" || return 1
  mask_value="$(_pdg_quic_u32 "$mask_token")" || return 1
  # A mark with significant bits outside its mask is not a well-defined
  # match-set representation. Never normalize malformed foreign output.
  (( (mark_value & mask_value) == mark_value )) || return 1
  printf '%u|%u\n' "$mark_value" "$mask_value"
}

_pdg_quic_mark_sets_overlap(){
  local am ax bm bx
  am="$(_pdg_quic_u32 "$1")" || return 2
  ax="$(_pdg_quic_u32 "$2")" || return 2
  bm="$(_pdg_quic_u32 "$3")" || return 2
  bx="$(_pdg_quic_u32 "$4")" || return 2
  (( (am & ax) == am && (bm & bx) == bm )) || return 2
  # (packet & ax)==am and (packet & bx)==bm have a common solution iff
  # their requirements agree on every bit constrained by both masks.
  (( ((am ^ bm) & ax & bx) == 0 ))
}

# Sets PDG_Q_RULE_EXACT, PDG_Q_ROUTE_EXACT and conflict counters.
_pdg_quic_inspect(){
  local mark="$1" mask="$2" table="$3" priority="$4"
  [[ -n "$PDG_QUIC_IP" && -x "$PDG_QUIC_IP" ]] || {
    echo "找不到 iproute2 的 ip" >&2; return 1; }
  local rules routes line route_err route_err_file target_mark target_mask target_table
  local exact rule_table table_token mark_token parsed rule_mark rule_mask
  local mark_tail has_fwmark table_value
  target_mark="$(_pdg_quic_u32 "$mark")" || {
    echo "QUIC profile mark 非法" >&2; return 1; }
  target_mask="$(_pdg_quic_u32 "$mask")" || {
    echo "QUIC profile mask 非法" >&2; return 1; }
  target_table="$(_pdg_quic_u32 "$table")" || {
    echo "QUIC profile route table 非法" >&2; return 1; }
  (( (target_mark & target_mask) == target_mark )) || {
    echo "QUIC profile mark 含 mask 外位" >&2; return 1; }
  PDG_Q_RULE_EXACT=0 PDG_Q_ROUTE_EXACT=0
  PDG_Q_PRIORITY_FOREIGN=0 PDG_Q_TUPLE_ELSEWHERE=0 PDG_Q_ROUTE_FOREIGN=0
  PDG_Q_TARGET_TABLE_FOREIGN=0 PDG_Q_MARK_OVERLAP_FOREIGN=0
  PDG_Q_RULE_UNPARSEABLE=0
  rules="$("$PDG_QUIC_IP" -4 rule show 2>/dev/null)" || {
    echo "读不到 IPv4 policy rules，拒绝盲写" >&2; return 1; }
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    exact=0 rule_table="" table_token="" has_fwmark=0
    if _pdg_quic_rule_exact "$line" "$priority" "$mark" "$mask" "$table"; then
      PDG_Q_RULE_EXACT=$((PDG_Q_RULE_EXACT + 1)); exact=1
    fi
    if (( exact == 0 )) && [[ "$line" =~ ^[[:space:]]*${priority}: ]]; then
      PDG_Q_PRIORITY_FOREIGN=$((PDG_Q_PRIORITY_FOREIGN + 1))
    fi
    if [[ "$line" =~ (^|[[:space:]])(lookup|table)[[:space:]]+([^[:space:]]+) ]]; then
      table_token="${BASH_REMATCH[3]}"
      if [[ "$table_token" =~ ^[0-9]+$ ]]; then
        if ! table_value="$(_pdg_quic_u32 "$table_token")"; then
          PDG_Q_RULE_UNPARSEABLE=$((PDG_Q_RULE_UNPARSEABLE + 1))
          continue
        fi
        (( table_value == target_table )) && rule_table="$table_token"
      elif [[ "$table_token" != local && "$table_token" != main \
              && "$table_token" != default ]]; then
        # A custom rt_tables name may resolve to our numeric target. Without
        # resolving the same namespace as iproute2, treating it as unrelated
        # could orphan or overwrite a foreign rule.
        PDG_Q_RULE_UNPARSEABLE=$((PDG_Q_RULE_UNPARSEABLE + 1))
        continue
      fi
    fi
    if (( exact == 0 )) && [[ -n "$rule_table" ]]; then
      PDG_Q_TARGET_TABLE_FOREIGN=$((PDG_Q_TARGET_TABLE_FOREIGN + 1))
    fi
    if [[ "$line" =~ (^|[[:space:]])fwmark([[:space:]]|$) ]]; then
      has_fwmark=1
    fi
    if (( has_fwmark )); then
      # Parse the complete grammar, not just fwmark/table substrings. Extra
      # selectors/actions ("not", "from CIDR", goto, suppress, ...) make this
      # foreign rule's semantics unknowable and therefore fail closed.
      if ! [[ "$line" =~ ^[[:space:]]*[0-9]+:[[:space:]]+from[[:space:]]+all[[:space:]]+fwmark[[:space:]]+[^[:space:]]+[[:space:]]+(lookup|table)[[:space:]]+[^[:space:]]+[[:space:]]*$ ]]; then
        PDG_Q_RULE_UNPARSEABLE=$((PDG_Q_RULE_UNPARSEABLE + 1))
        continue
      fi
      if [[ "$line" =~ (^|[[:space:]])fwmark[[:space:]]+([^[:space:]]+) ]]; then
        mark_token="${BASH_REMATCH[2]}"
        mark_tail="${line#*fwmark}"
        if [[ "$mark_tail" == *fwmark* ]] \
           || ! parsed="$(_pdg_quic_parse_mark_token "$mark_token")"; then
          PDG_Q_RULE_UNPARSEABLE=$((PDG_Q_RULE_UNPARSEABLE + 1))
          continue
        fi
        IFS='|' read -r rule_mark rule_mask <<<"$parsed"
        if (( exact == 0 )) \
           && (( ((rule_mark ^ target_mark) & rule_mask & target_mask) == 0 )); then
          PDG_Q_MARK_OVERLAP_FOREIGN=$((PDG_Q_MARK_OVERLAP_FOREIGN + 1))
        fi
        if (( exact == 0 )) && [[ -n "$rule_table" ]] \
           && (( rule_mark == target_mark && rule_mask == target_mask )); then
          PDG_Q_TUPLE_ELSEWHERE=$((PDG_Q_TUPLE_ELSEWHERE + 1))
        fi
      else
        PDG_Q_RULE_UNPARSEABLE=$((PDG_Q_RULE_UNPARSEABLE + 1))
      fi
    fi
  done <<<"$rules"
  route_err_file="$(mktemp)" || return 1
  if ! routes="$("$PDG_QUIC_IP" -4 route show table "$table" \
      2>"$route_err_file")"; then
    route_err="$(cat "$route_err_file" 2>/dev/null)"
    # iproute2 returns exit 2 for an unused numeric table on some releases.
    # Treat only its exact FIB-table-absent diagnostic as a clean empty table;
    # permission/netlink/parser failures remain fail closed.
    if [[ -z "$routes" ]] \
      && [[ "$route_err" =~ ^Error:\ (ipv4:\ )?FIB\ table\ does\ not\ exist\.?($|[[:space:]]+Dump\ terminated\.?$) ]]; then
      routes=""
    else
      rm -f "$route_err_file"
      echo "读不到 QUIC route table $table，拒绝盲写: $route_err" >&2
      return 1
    fi
  fi
  rm -f "$route_err_file"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    if _pdg_quic_route_exact "$line"; then
      PDG_Q_ROUTE_EXACT=$((PDG_Q_ROUTE_EXACT + 1))
    else
      PDG_Q_ROUTE_FOREIGN=$((PDG_Q_ROUTE_FOREIGN + 1))
    fi
  done <<<"$routes"
}

# $5=trusted state proves an existing exact tuple is ours.
_pdg_quic_preflight_values(){
  local mark="$1" mask="$2" table="$3" priority="$4" trusted="${5:-0}"
  _pdg_quic_inspect "$mark" "$mask" "$table" "$priority" || return 1
  if (( PDG_Q_PRIORITY_FOREIGN || PDG_Q_TUPLE_ELSEWHERE \
        || PDG_Q_TARGET_TABLE_FOREIGN || PDG_Q_MARK_OVERLAP_FOREIGN \
        || PDG_Q_RULE_UNPARSEABLE \
        || PDG_Q_ROUTE_FOREIGN || PDG_Q_RULE_EXACT > 1 \
        || PDG_Q_ROUTE_EXACT > 1 )); then
    echo "QUIC policy-routing 目标与现有 rule/route 冲突" >&2
    return 1
  fi
  # Shape equality is not provenance. First run may not adopt a foreign exact
  # tuple and later delete it; only our strict state file grants ownership.
  if [[ "$trusted" != 1 ]] \
    && (( PDG_Q_RULE_EXACT || PDG_Q_ROUTE_EXACT )); then
    echo "发现无可信 PDG state 的 exact QUIC tuple，按 foreign 拒绝接管" >&2
    return 1
  fi
}

pdg_quic_preflight(){
  _pdg_quic_load_profile || return 1
  local state_rc=1 trusted=0
  _pdg_quic_load_state; state_rc=$?
  [[ "$state_rc" != 2 ]] || return 1
  if [[ "$state_rc" == 0 \
        && "$PDG_QS_MARK|$PDG_QS_MASK|$PDG_QS_TABLE|$PDG_QS_PRIORITY" \
           == "$PDG_Q_MARK|$PDG_Q_MASK|$PDG_Q_TABLE|$PDG_Q_PRIORITY" ]]; then
    trusted=1
  fi
  [[ "$PDG_Q_MODE" == reject ]] && return 0
  if [[ "$state_rc" == 0 && "$trusted" == 0 ]]; then
    _pdg_quic_preflight_migration_values \
      "$PDG_Q_MARK" "$PDG_Q_MASK" "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" \
      "$PDG_QS_MARK" "$PDG_QS_MASK" "$PDG_QS_TABLE" "$PDG_QS_PRIORITY"
    return $?
  fi
  _pdg_quic_preflight_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
    "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" "$trusted"
}

_pdg_quic_remove_values(){
  local mark="$1" mask="$2" table="$3" priority="$4"
  _pdg_quic_inspect "$mark" "$mask" "$table" "$priority" || return 1
  (( PDG_Q_PRIORITY_FOREIGN == 0 && PDG_Q_TUPLE_ELSEWHERE == 0 \
     && PDG_Q_TARGET_TABLE_FOREIGN == 0 \
     && PDG_Q_MARK_OVERLAP_FOREIGN == 0 \
     && PDG_Q_RULE_UNPARSEABLE == 0 \
     && PDG_Q_ROUTE_FOREIGN == 0 && PDG_Q_RULE_EXACT <= 1 \
     && PDG_Q_ROUTE_EXACT <= 1 )) || return 1
  local removed_rule=0
  if (( PDG_Q_RULE_EXACT == 1 )); then
    "$PDG_QUIC_IP" -4 rule del priority "$priority" \
      fwmark "$mark/$mask" lookup "$table" >/dev/null 2>&1 || return 1
    removed_rule=1
  fi
  if (( PDG_Q_ROUTE_EXACT == 1 )); then
    "$PDG_QUIC_IP" -4 route del local 0.0.0.0/0 dev lo table "$table" \
      >/dev/null 2>&1 || {
        if [[ "$removed_rule" == 1 ]]; then
          "$PDG_QUIC_IP" -4 rule add priority "$priority" \
            fwmark "$mark/$mask" lookup "$table" >/dev/null 2>&1 || true
        fi
        return 1
      }
  fi
}

_pdg_quic_setup_values(){
  local mark="$1" mask="$2" table="$3" priority="$4" trusted="$5"
  _pdg_quic_preflight_values "$mark" "$mask" "$table" "$priority" "$trusted" || return 1
  local added_rule=0
  if (( PDG_Q_RULE_EXACT == 0 )); then
    "$PDG_QUIC_IP" -4 rule add priority "$priority" \
      fwmark "$mark/$mask" lookup "$table" || return 1
    added_rule=1
  fi
  if ! "$PDG_QUIC_IP" -4 route replace local 0.0.0.0/0 dev lo table "$table"; then
    # First setup owns only the rule added by this invocation.  Never leave it
    # orphaned when the following route operation fails.
    if [[ "$added_rule" == 1 ]]; then
      "$PDG_QUIC_IP" -4 rule del priority "$priority" \
        fwmark "$mark/$mask" lookup "$table" >/dev/null 2>&1 || {
          echo "QUIC route setup 失败，且刚新增 rule 清理失败" >&2; return 1; }
    fi
    return 1
  fi
}

_pdg_quic_preflight_migration_values(){
  local nm="$1" nx="$2" nt="$3" np="$4" om="$5" ox="$6" ot="$7" op="$8"
  if { [[ "$nt" == "$ot" ]] && [[ "$np" != "$op" ]]; } \
     || { [[ "$nt" != "$ot" ]] && [[ "$np" == "$op" ]]; }; then
    echo "QUIC tuple migration 不支持仅复用 table 或 priority；请同时迁移二者或仅变更 mark/mask" >&2
    return 1
  fi
  if [[ "$nt" != "$ot" || "$np" != "$op" ]]; then
    _pdg_quic_preflight_values "$nm" "$nx" "$nt" "$np" 0
    return $?
  fi
  # Same priority/table mark-only migration: the priority and shared local
  # route are occupied solely by the tuple proven by strict trusted old state.
  _pdg_quic_inspect "$om" "$ox" "$ot" "$op" || return 1
  (( PDG_Q_RULE_EXACT == 1 && PDG_Q_ROUTE_EXACT == 1 \
      && PDG_Q_PRIORITY_FOREIGN == 0 && PDG_Q_TUPLE_ELSEWHERE == 0 \
      && PDG_Q_TARGET_TABLE_FOREIGN == 0 \
      && PDG_Q_MARK_OVERLAP_FOREIGN == 0 \
      && PDG_Q_RULE_UNPARSEABLE == 0 \
      && PDG_Q_ROUTE_FOREIGN == 0 )) || {
    echo "可信旧 QUIC tuple 不完整，拒绝 mark-only migration" >&2; return 1; }
  local expected_old_overlap=0 overlap_rc=1
  if _pdg_quic_mark_sets_overlap "$nm" "$nx" "$om" "$ox"; then
    expected_old_overlap=1
  else
    overlap_rc=$?
    [[ "$overlap_rc" != 2 ]] || {
      echo "QUIC migration mark/mask 非法" >&2; return 1; }
  fi
  _pdg_quic_inspect "$nm" "$nx" "$nt" "$np" || return 1
  (( PDG_Q_RULE_EXACT == 0 && PDG_Q_PRIORITY_FOREIGN == 1 \
      && PDG_Q_TUPLE_ELSEWHERE == 0 && PDG_Q_ROUTE_EXACT == 1 \
      && PDG_Q_TARGET_TABLE_FOREIGN == 1 \
      && PDG_Q_MARK_OVERLAP_FOREIGN == expected_old_overlap \
      && PDG_Q_RULE_UNPARSEABLE == 0 \
      && PDG_Q_ROUTE_FOREIGN == 0 )) || {
    echo "mark-only QUIC migration 目标存在非旧 owned tuple 冲突" >&2; return 1; }
}

_pdg_quic_write_state_values(){
  local mark="$1" mask="$2" table="$3" priority="$4" dir tmp
  dir="$(dirname "$PDG_QUIC_STATE")"; mkdir -p "$dir" || return 1
  tmp="$(mktemp "$dir/.quic-routing.state.XXXXXX")" || return 1
  if ! printf 'MARK=%s\nMASK=%s\nTABLE=%s\nPRIORITY=%s\n' \
      "$mark" "$mask" "$table" "$priority" >"$tmp" \
      || ! chmod 600 "$tmp" || ! mv -f "$tmp" "$PDG_QUIC_STATE"; then
    rm -f "$tmp"; return 1
  fi
}

pdg_quic_remove(){
  local state_rc=1
  _pdg_quic_load_state; state_rc=$?
  [[ "$state_rc" != 2 ]] || return 1
  # Missing trusted state means there is nothing we are authorized to delete.
  [[ "$state_rc" == 0 ]] || return 0
  _pdg_quic_remove_values "$PDG_QS_MARK" "$PDG_QS_MASK" \
    "$PDG_QS_TABLE" "$PDG_QS_PRIORITY" || return 1
  rm -f "$PDG_QUIC_STATE"
}

pdg_quic_apply(){
  _pdg_quic_load_profile || return 1
  local state_rc=1
  _pdg_quic_load_state; state_rc=$?
  [[ "$state_rc" != 2 ]] || return 1
  if [[ "$PDG_Q_MODE" == reject ]]; then
    pdg_quic_remove
    return $?
  fi
  if [[ "$state_rc" != 0 ]]; then
    _pdg_quic_setup_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
      "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" 0 || return 1
    if ! _pdg_quic_write_state_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
        "$PDG_Q_TABLE" "$PDG_Q_PRIORITY"; then
      # This tuple was created by this invocation, so exact removal is owned.
      _pdg_quic_remove_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
        "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" || true
      return 1
    fi
    return 0
  fi
  if [[ "$PDG_QS_MARK|$PDG_QS_MASK|$PDG_QS_TABLE|$PDG_QS_PRIORITY" \
        == "$PDG_Q_MARK|$PDG_Q_MASK|$PDG_Q_TABLE|$PDG_Q_PRIORITY" ]]; then
    _pdg_quic_setup_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
      "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" 1 || return 1
    return 0
  fi

  # Tuple migration: prove the new destination is clean before touching old.
  _pdg_quic_preflight_migration_values \
    "$PDG_Q_MARK" "$PDG_Q_MASK" "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" \
    "$PDG_QS_MARK" "$PDG_QS_MASK" "$PDG_QS_TABLE" "$PDG_QS_PRIORITY" \
    || return 1
  _pdg_quic_remove_values "$PDG_QS_MARK" "$PDG_QS_MASK" \
    "$PDG_QS_TABLE" "$PDG_QS_PRIORITY" || return 1
  if ! _pdg_quic_setup_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
      "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" 0 \
    || ! _pdg_quic_write_state_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
      "$PDG_Q_TABLE" "$PDG_Q_PRIORITY"; then
    # Roll back the just-created new tuple, then recreate exactly the trusted
    # old tuple and state.  Failure is loud and leaves the old state file.
    _pdg_quic_remove_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
      "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" || true
    _pdg_quic_setup_values "$PDG_QS_MARK" "$PDG_QS_MASK" \
      "$PDG_QS_TABLE" "$PDG_QS_PRIORITY" 0 || return 1
    _pdg_quic_write_state_values "$PDG_QS_MARK" "$PDG_QS_MASK" \
      "$PDG_QS_TABLE" "$PDG_QS_PRIORITY" || return 1
    return 1
  fi
}

pdg_quic_status(){
  _pdg_quic_load_profile || return 1
  local state_rc=1
  _pdg_quic_load_state; state_rc=$?
  [[ "$state_rc" != 2 ]] || return 1
  if [[ "$PDG_Q_MODE" == reject ]]; then
    [[ "$state_rc" != 0 ]] || {
      echo "reject 模式仍有可信 PDG routing state" >&2; return 1; }
    _pdg_quic_preflight_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
      "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" 0 || return 1
    echo "reject (无 PDG policy route)"
    return 0
  fi
  [[ "$state_rc" == 0 ]] || {
    echo "tproxy 模式缺少可信 PDG routing state" >&2; return 1; }
  [[ "$PDG_QS_MARK|$PDG_QS_MASK|$PDG_QS_TABLE|$PDG_QS_PRIORITY" \
      == "$PDG_Q_MARK|$PDG_Q_MASK|$PDG_Q_TABLE|$PDG_Q_PRIORITY" ]] || {
    echo "QUIC routing state 与 profile tuple 不一致" >&2; return 1; }
  _pdg_quic_preflight_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
    "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" 1 || return 1
  (( PDG_Q_RULE_EXACT == 1 && PDG_Q_ROUTE_EXACT == 1 )) || {
    echo "可信 QUIC rule/route 缺失" >&2; return 1; }
  echo "tproxy mark=$PDG_Q_MARK/$PDG_Q_MASK table=$PDG_Q_TABLE priority=$PDG_Q_PRIORITY"
}

pdg_quic_cleanup_status(){
  # Read-only uninstall proof. A successful remove with no state is not
  # sufficient: without provenance remove intentionally deletes nothing.
  _pdg_quic_load_profile || return 1
  local state_rc=1
  _pdg_quic_load_state; state_rc=$?
  [[ "$state_rc" != 2 ]] || return 1
  [[ "$state_rc" != 0 ]] || {
    echo "QUIC cleanup 后仍有可信 state" >&2; return 1; }
  _pdg_quic_preflight_values "$PDG_Q_MARK" "$PDG_Q_MASK" \
    "$PDG_Q_TABLE" "$PDG_Q_PRIORITY" 0 || return 1
  echo "clean (无可信 state，profile tuple 未占用)"
}

pdg_quic_rollback_state(){
  # Internal transaction rollback used after nft/profile application fails.
  # FILE must be the caller's before-image of our already validated state; "-"
  # means there was no trusted state before the transaction.
  local before="${1:-}" active="$PDG_QUIC_STATE"
  [[ "$before" == - || -f "$before" ]] || {
    echo "QUIC rollback state before-image 缺失" >&2; return 1; }
  local om="" ox="" ot="" op=""
  if [[ "$before" != - ]]; then
    PDG_QUIC_STATE="$before"
    _pdg_quic_load_state || { PDG_QUIC_STATE="$active"; return 1; }
    om="$PDG_QS_MARK"; ox="$PDG_QS_MASK"
    ot="$PDG_QS_TABLE"; op="$PDG_QS_PRIORITY"
    PDG_QUIC_STATE="$active"
  fi
  # Remove only the current trusted active tuple. Missing state is a no-op;
  # corrupt state is loud and leaves both kernel and before-image untouched.
  pdg_quic_remove || return 1
  if [[ "$before" == - ]]; then
    return 0
  fi
  if ! _pdg_quic_setup_values "$om" "$ox" "$ot" "$op" 0 \
    || ! _pdg_quic_write_state_values "$om" "$ox" "$ot" "$op"; then
    _pdg_quic_remove_values "$om" "$ox" "$ot" "$op" || true
    return 1
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -uo pipefail
  case "${1:-}" in
    preflight) pdg_quic_preflight;;
    apply) pdg_quic_apply;;
    remove) pdg_quic_remove;;
    status) pdg_quic_status;;
    cleanup-status) pdg_quic_cleanup_status;;
    rollback-state) shift; pdg_quic_rollback_state "${1:-}";;
    *) echo "用法: $0 preflight|apply|remove|status|cleanup-status|rollback-state FILE" >&2; exit 2;;
  esac
fi
