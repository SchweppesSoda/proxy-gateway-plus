#!/usr/bin/env bash
# Fault-injection regression for the host-safety boundary of E2E namespaces.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)" \
  || { echo "FAIL: cannot resolve repository root" >&2; exit 1; }
TMP_ROOT="$(cd "${TMPDIR:-/tmp}" 2>/dev/null && pwd -P)" \
  || { echo "FAIL: cannot resolve temporary root" >&2; exit 1; }
[[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]] \
  || { echo "FAIL: untrusted temporary root" >&2; exit 1; }
WORK="$(mktemp -d "$TMP_ROOT/pdg-e2e-safety.XXXXXX")" \
  || { echo "FAIL: cannot create safety-test workdir" >&2; exit 1; }
case "$WORK" in
  "$TMP_ROOT"/pdg-e2e-safety.*)
    [[ -d "$WORK" && ! -L "$WORK" ]] \
      || { echo "FAIL: unsafe safety-test workdir" >&2; exit 1; }
    ;;
  *) echo "FAIL: unsafe safety-test workdir" >&2; exit 1 ;;
esac

cleanup(){
  case "${WORK:-}" in
    "$TMP_ROOT"/pdg-e2e-safety.*)
      [[ -d "$WORK" && ! -L "$WORK" ]] || return 0
      rm -rf -- "$WORK"
      ;;
    *) echo "FAIL: refusing unsafe safety-test cleanup" >&2; return 1 ;;
  esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

die(){ echo "FAIL: $*" >&2; exit 1; }
pass=0
ok(){ echo "OK: $*"; pass=$((pass+1)); }

# Known host paths protected by the namespace boundary.  Keep this explicit and
# bounded: never replace it with a recursive fingerprint of all /usr/local.
PDG_HOST_TARGETS=(
  /etc/gitconfig /etc/nftables.conf
  /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
  /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh.pdg-preinstall
  /etc/systemd/system/pdg-quic-routing.service
  /etc/systemd/system/pdg-quic-routing.service.pdg-preinstall
  /etc/systemd/system/pdg-web.service
  /etc/systemd/system/pdg-web.service.pdg-preinstall
  /usr/local/bin/pdg /usr/local/bin/pdg-webctl
  /usr/local/bin/pdg-webctl.pdg-preinstall
  /usr/local/bin/mihomo /usr/local/bin/mihomo.pdg-preinstall
  /usr/local/bin/mosdns /usr/local/bin/mosdns.pdg-preinstall
  /usr/local/bin/mosdns.e2e-real /usr/local/sbin
  /usr/local/libexec/pdg-quic-routing.sh
  /usr/local/libexec/pdg-quic-routing.sh.pdg-preinstall
  /opt/pdg-bot /opt/pdg-web
  /var/lib/privdns-gateway
)

host_target_listed(){
  local wanted="$1" path
  for path in "${PDG_HOST_TARGETS[@]}"; do
    [[ "$path" == "$wanted" ]] && return 0
  done
  return 1
}

validate_host_target_contract(){
  local path call stash stash_count=0 declared_stash_count listed_stash_count=0
  for path in /usr/local/bin/mosdns.e2e-real /usr/local/sbin \
      /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh; do
    host_target_listed "$path" || die "host fingerprint omits required target: $path"
  done

  # Lock the explicit list to the three production/E2E write surfaces.  Every
  # install transaction stash requires both its target and deterministic
  # .pdg-preinstall sibling; newly added _stash_bin calls fail this test until
  # their host fingerprint coverage is added.
  while IFS= read -r call; do
    if [[ "$call" =~ ^[[:space:]]*_stash_bin[[:space:]]+(/[-A-Za-z0-9._+/]+)([[:space:]]|$) ]]; then
      stash="${BASH_REMATCH[1]}"
    else
      die "_stash_bin call must use one literal absolute target: $call"
    fi
    stash_count=$((stash_count+1))
    host_target_listed "$stash" \
      || die "host fingerprint omits _stash_bin target: $stash"
    host_target_listed "$stash.pdg-preinstall" \
      || die "host fingerprint omits _stash_bin sibling: $stash.pdg-preinstall"
  done < <(grep -E '^[[:space:]]*_stash_bin([[:space:]]|$)' "$ROOT/install.sh")
  declared_stash_count="$(grep -Ec \
    '^[[:space:]]*_stash_bin([[:space:]]|$)' "$ROOT/install.sh")"
  for path in "${PDG_HOST_TARGETS[@]}"; do
    [[ "$path" == *.pdg-preinstall ]] \
      && listed_stash_count=$((listed_stash_count+1))
  done
  [[ "$stash_count" -gt 0 && "$stash_count" -eq "$declared_stash_count" \
     && "$stash_count" -eq "$listed_stash_count" ]] \
    || die "cannot close host fingerprint over install.sh _stash_bin calls"

  grep -Fqx \
    '        run: timeout --foreground --kill-after=5s 60s bash tests/test-e2e-overlay-safety.sh' \
    "$ROOT/.github/workflows/ci.yml" \
    || die "CI overlay safety step lacks the exact 60-second watchdog"
  grep -Fq 'HOST_USR_LOCAL_BEFORE="$(pdg_usr_local_sentinel)"' \
    "$ROOT/tests/e2e-serial-hermetic.sh" \
    && grep -Fq 'HOST_USR_LOCAL_AFTER="$(pdg_usr_local_sentinel)"' \
      "$ROOT/tests/e2e-serial-hermetic.sh" \
    || die "normal serial path lost its before/after full /usr/local sentinel"
}

# Emit one stable record per target.  Callers compare the complete record set,
# so a failure names the protected surface instead of hiding it behind one hash.
fingerprint_path(){
  local path="$1" digest metadata
  if [[ -L "$path" ]]; then
    metadata="$(stat -c '%F:%f:%a:%u:%g' -- "$path")" || return 1
    printf 'link\t%s\t%s\t%s\n' "$path" "$metadata" "$(readlink "$path")"
  elif [[ -f "$path" ]]; then
    metadata="$(stat -c '%F:%f:%a:%u:%g' -- "$path")" || return 1
    digest="$(timeout --kill-after=1s 10s sha256sum -- "$path" | awk '{print $1}')" \
      || return 1
    printf 'file\t%s\t%s\t%s\n' "$path" "$metadata" "$digest"
  elif [[ -d "$path" ]]; then
    metadata="$(stat -c '%F:%f:%a:%u:%g' -- "$path")" || return 1
    digest="$(timeout --kill-after=1s 10s tar --sort=name --mtime='@0' \
      --numeric-owner --one-file-system -cf - -C "$path" . \
      | sha256sum | awk '{print $1}')" || return 1
    printf 'dir\t%s\t%s\t%s\n' "$path" "$metadata" "$digest"
  elif [[ -e "$path" ]]; then
    metadata="$(stat -c '%F:%f:%a:%u:%g:%s' -- "$path")" || return 1
    printf 'other\t%s\t%s\n' "$path" "$metadata"
  else
    printf 'missing\t%s\n' "$path"
  fi
}

host_targets_fingerprint(){
  local path
  for path in "${PDG_HOST_TARGETS[@]}"; do
    fingerprint_path "$path" || return 1
  done
}

write_wrapper(){
  local wrapper="$1"
  cat > "$wrapper" <<'WRAPPER'
#!/usr/bin/env bash
set -uo pipefail
source "$E2E_ROOT/tests/e2e-lib.sh"
e2e_enter "$@"
printf 'body-ran\n' > "$PDG_FAULT_BODY_MARKER"
WRAPPER
  chmod 700 "$wrapper"
}

write_common_stubs(){
  local bindir="$1"
  mkdir -p "$bindir"
  cat > "$bindir/unshare" <<'STUB'
#!/usr/bin/env bash
printf 'unshare %s\n' "$*" >> "$PDG_FAULT_CALL_LOG"
exit 0
STUB
  cat > "$bindir/mktemp" <<'STUB'
#!/usr/bin/env bash
printf 'mktemp %s\n' "$*" >> "$PDG_FAULT_CALL_LOG"
exit 96
STUB
  cat > "$bindir/tar" <<'STUB'
#!/usr/bin/env bash
printf 'tar %s\n' "$*" >> "$PDG_FAULT_CALL_LOG"
printf 'bounded-overlay-safety-sentinel\n'
STUB
  cat > "$bindir/mkdir" <<'STUB'
#!/usr/bin/env bash
printf 'mkdir %s\n' "$*" >> "$PDG_FAULT_WRITE_LOG"
exit 97
STUB
  cat > "$bindir/rm" <<'STUB'
#!/usr/bin/env bash
printf 'rm %s\n' "$*" >> "$PDG_FAULT_WRITE_LOG"
exit 98
STUB
  chmod 700 "$bindir"/*
}

write_success_mktemp_stubs(){
  local bindir="$1"
  write_common_stubs "$bindir"
  cat > "$bindir/unshare" <<'STUB'
#!/usr/bin/env bash
printf 'unshare %s\n' "$*" >> "$PDG_FAULT_CALL_LOG"
exit 0
STUB
  cat > "$bindir/mktemp" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
printf 'mktemp %s\n' "$*" >> "$PDG_FAULT_CALL_LOG"
created="$("$PDG_FAULT_REAL_MKTEMP" "$@")" || exit $?
printf 'created %s\n' "$created" >> "$PDG_FAULT_CALL_LOG"
printf '%s\n' "$created"
STUB
  cat > "$bindir/rm" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
printf 'rm %s\n' "$*" >> "$PDG_FAULT_WRITE_LOG"
exec "$PDG_FAULT_REAL_RM" "$@"
STUB
  chmod 700 "$bindir"/*
}

write_mount_stubs(){
  local bindir="$1"
  mkdir -p "$bindir"
  cat > "$bindir/mount" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
count=0
if [[ -f "$PDG_FAULT_MOUNT_COUNT" ]]; then
  IFS= read -r count < "$PDG_FAULT_MOUNT_COUNT"
fi
count=$((count+1))
printf '%s\n' "$count" > "$PDG_FAULT_MOUNT_COUNT"
printf 'mount[%s] %s\n' "$count" "$*" >> "$PDG_FAULT_CALL_LOG"
if [[ "$count" -eq "$PDG_FAULT_MOUNT_FAIL_AT" ]]; then
  exit 99
fi
exit 0
STUB
  cat > "$bindir/mkdir" <<'STUB'
#!/usr/bin/env bash
printf 'mkdir %s\n' "$*" >> "$PDG_FAULT_WRITE_LOG"
exit 97
STUB
  chmod 700 "$bindir"/*
}

assert_failure_is_inert(){
  local case_dir="$1" before="$2" after="$3" marker="$4"
  [[ "$before" == "$after" ]] || die "$case_dir changed a protected host target"
  [[ ! -e "$marker" ]] || die "$case_dir executed the E2E body"
  [[ ! -s "$case_dir/write.log" ]] || die "$case_dir attempted a host write"
}

run_fingerprint_contract(){
  local case_dir="$WORK/fingerprint-contract" baseline mode_changed restored content_changed
  local before_mode after_mode mode_verified=0
  local -a saved_targets=("${PDG_HOST_TARGETS[@]}")
  mkdir -p "$case_dir/managed"
  printf 'stable\n' > "$case_dir/managed/listed.txt"
  printf 'alpha\n' > "$case_dir/managed/unlisted.txt"
  chmod 700 "$case_dir/managed"
  chmod 600 "$case_dir/managed/listed.txt" "$case_dir/managed/unlisted.txt"
  PDG_HOST_TARGETS=("$case_dir/managed")

  baseline="$(host_targets_fingerprint)" \
    || die "cannot create baseline managed-fixture fingerprint"
  before_mode="$(stat -c '%a' "$case_dir/managed/unlisted.txt")"
  chmod 640 "$case_dir/managed/unlisted.txt"
  after_mode="$(stat -c '%a' "$case_dir/managed/unlisted.txt")"
  if [[ "$after_mode" != "$before_mode" ]]; then
    mode_changed="$(host_targets_fingerprint)" \
      || die "cannot fingerprint managed-fixture mode change"
    [[ "$mode_changed" != "$baseline" ]] \
      || die "managed directory fingerprint ignored a child mode-only change"
    chmod "$before_mode" "$case_dir/managed/unlisted.txt"
    restored="$(host_targets_fingerprint)" \
      || die "cannot fingerprint restored managed fixture"
    [[ "$restored" == "$baseline" ]] \
      || die "managed directory fingerprint is unstable after restoring metadata"
    mode_verified=1
  else
    [[ "$(uname -s)" != Linux ]] \
      || die "Linux fixture filesystem failed to expose chmod metadata changes"
    echo "SKIP: non-Linux fixture filesystem does not expose chmod metadata changes"
  fi
  printf 'bravo\n' > "$case_dir/managed/unlisted.txt"
  content_changed="$(host_targets_fingerprint)" \
    || die "cannot fingerprint unlisted managed-fixture content change"
  [[ "$content_changed" != "$baseline" ]] \
    || die "managed directory fingerprint ignored an unlisted child content change"

  PDG_HOST_TARGETS=("${saved_targets[@]}")
  if [[ "$mode_verified" -eq 1 ]]; then
    ok "host fingerprint detects metadata-only and unlisted-child changes"
  else
    ok "host fingerprint detects unlisted-child content changes"
  fi
}

run_common_mktemp_failure(){
  local case_dir="$WORK/common-mktemp" before after wrapper marker
  mkdir -p "$case_dir/tmp"
  wrapper="$case_dir/wrapper.sh"; marker="$case_dir/body.marker"
  write_wrapper "$wrapper"
  write_common_stubs "$case_dir/bin"
  before="$(host_targets_fingerprint)" || die "cannot hash host before common mktemp case"
  if env PATH="$case_dir/bin:$PATH" TMPDIR="$case_dir/tmp" E2E_ROOT="$ROOT" \
      PDG_FAULT_BODY_MARKER="$marker" PDG_FAULT_CALL_LOG="$case_dir/calls.log" \
      PDG_FAULT_WRITE_LOG="$case_dir/write.log" bash "$wrapper" \
      > "$case_dir/output.log" 2>&1; then
    die "common helper accepted mktemp failure"
  fi
  after="$(host_targets_fingerprint)" || die "cannot hash host after common mktemp case"
  assert_failure_is_inert "$case_dir" "$before" "$after" "$marker"
  grep -q '^mktemp ' "$case_dir/calls.log" \
    || die "common mktemp fault was not reached"
  ok "e2e_enter fails closed when mktemp fails"
}

run_serial_mktemp_failure(){
  local case_dir="$WORK/serial-mktemp" before after
  mkdir -p "$case_dir/tmp"
  write_common_stubs "$case_dir/bin"
  before="$(host_targets_fingerprint)" || die "cannot hash host before serial mktemp case"
  if env PATH="$case_dir/bin:$PATH" TMPDIR="$case_dir/tmp" \
      PDG_FAULT_CALL_LOG="$case_dir/calls.log" \
      PDG_FAULT_WRITE_LOG="$case_dir/write.log" \
      bash "$ROOT/tests/e2e-serial-hermetic.sh" \
      __test-only-overlay-mktemp-failure \
      > "$case_dir/output.log" 2>&1; then
    die "serial helper accepted mktemp failure"
  fi
  after="$(host_targets_fingerprint)" || die "cannot hash host after serial mktemp case"
  assert_failure_is_inert "$case_dir" "$before" "$after" "$case_dir/body.marker"
  grep -q '^mktemp ' "$case_dir/calls.log" \
    || die "serial mktemp fault was not reached"
  if grep -q '^tar ' "$case_dir/calls.log"; then
    die "test-only serial mktemp probe entered the full-tree sentinel"
  fi
  if grep -q '^串行顺序:' "$case_dir/output.log"; then
    die "serial body started after mktemp failure"
  fi
  ok "serial helper fails closed when mktemp fails"
}

run_serial_success_mktemp_cleanup(){
  local case_dir="$WORK/serial-mktemp-success" before after created rc=0
  local real_mktemp real_rm
  real_mktemp="$(command -v mktemp)"
  real_rm="$(command -v rm)"
  [[ "$real_mktemp" == /* && -x "$real_mktemp" \
     && "$real_rm" == /* && -x "$real_rm" ]] \
    || die "cannot resolve real mktemp/rm for serial cleanup contract"
  mkdir -p "$case_dir/tmp"
  write_success_mktemp_stubs "$case_dir/bin"
  before="$(host_targets_fingerprint)" \
    || die "cannot fingerprint host before successful serial mktemp case"
  env PATH="$case_dir/bin:$PATH" TMPDIR="$case_dir/tmp" \
      PDG_FAULT_REAL_MKTEMP="$real_mktemp" PDG_FAULT_REAL_RM="$real_rm" \
      PDG_FAULT_CALL_LOG="$case_dir/calls.log" \
      PDG_FAULT_WRITE_LOG="$case_dir/write.log" \
      bash "$ROOT/tests/e2e-serial-hermetic.sh" \
      __test-only-overlay-mktemp-failure \
      > "$case_dir/output.log" 2>&1 || rc=$?
  [[ "$rc" -eq 97 ]] \
    || die "successful test-only serial mktemp returned $rc instead of 97"
  after="$(host_targets_fingerprint)" \
    || die "cannot fingerprint host after successful serial mktemp case"
  [[ "$before" == "$after" ]] \
    || die "successful serial mktemp cleanup changed a protected host target"
  created="$(sed -n 's/^created //p' "$case_dir/calls.log")"
  case "$created" in
    "$case_dir"/tmp/pdg-e2e-serial.*) ;;
    *) die "successful serial mktemp returned an unsafe path: $created" ;;
  esac
  [[ ! -e "$created" ]] || die "successful serial mktemp overlay was not removed"
  [[ ! -e "$case_dir/body.marker" ]] \
    || die "successful test-only serial mktemp executed an E2E body"
  if grep -q '^串行顺序:' "$case_dir/output.log"; then
    die "serial body started in successful test-only mktemp probe"
  fi
  if grep -q '^tar ' "$case_dir/calls.log"; then
    die "successful test-only serial mktemp entered the full-tree sentinel"
  fi
  grep -q '^unshare ' "$case_dir/calls.log" \
    || die "successful serial mktemp cleanup did not try namespace cleanup"
  [[ "$(wc -l < "$case_dir/write.log")" -eq 1 ]] \
    || die "successful serial mktemp cleanup issued unexpected writes"
  grep -Fqx "rm -rf -- $created" "$case_dir/write.log" \
    || die "successful serial mktemp did not use the validated direct-rm fallback"
  ok "successful test-only mktemp cleans up after no-op unshare and returns 97"
}

run_common_mount_failure(){
  local fail_at="$1" case_dir="$WORK/common-mount-$1" before after wrapper marker count
  mkdir -p "$case_dir/tmp/pdg-e2e-overlay.case"/{eu,ew,bu,bw,ou,ow,vu,vw}
  wrapper="$case_dir/wrapper.sh"; marker="$case_dir/body.marker"
  write_wrapper "$wrapper"
  write_mount_stubs "$case_dir/bin"
  before="$(host_targets_fingerprint)" || die "cannot hash host before common mount $fail_at"
  if env PATH="$case_dir/bin:$PATH" E2E_ROOT="$ROOT" PDG_E2E_INNER=1 \
      E2E_TMP_ROOT="$case_dir/tmp" E2E_OVL="$case_dir/tmp/pdg-e2e-overlay.case" \
      PDG_FAULT_BODY_MARKER="$marker" PDG_FAULT_CALL_LOG="$case_dir/calls.log" \
      PDG_FAULT_WRITE_LOG="$case_dir/write.log" \
      PDG_FAULT_MOUNT_COUNT="$case_dir/mount.count" \
      PDG_FAULT_MOUNT_FAIL_AT="$fail_at" bash "$wrapper" \
      > "$case_dir/output.log" 2>&1; then
    die "common helper accepted mount failure $fail_at"
  fi
  after="$(host_targets_fingerprint)" || die "cannot hash host after common mount $fail_at"
  assert_failure_is_inert "$case_dir" "$before" "$after" "$marker"
  IFS= read -r count < "$case_dir/mount.count"
  [[ "$count" -eq "$fail_at" ]] || die "common helper continued after mount failure $fail_at"
  ok "e2e_enter mount failure $fail_at prevents all body and host writes"
}

run_serial_mount_failure(){
  local fail_at="$1" case_dir="$WORK/serial-mount-$1" before after count
  mkdir -p "$case_dir/tmp/pdg-e2e-serial.case"/{eu,ew,bu,bw,ou,ow,vu,vw}
  write_mount_stubs "$case_dir/bin"
  before="$(host_targets_fingerprint)" || die "cannot hash host before serial mount $fail_at"
  if env PATH="$case_dir/bin:$PATH" PDG_SERIAL_INNER=1 \
      PDG_SERIAL_TMP_ROOT="$case_dir/tmp" OVL="$case_dir/tmp/pdg-e2e-serial.case" \
      PDG_FAULT_CALL_LOG="$case_dir/calls.log" \
      PDG_FAULT_WRITE_LOG="$case_dir/write.log" \
      PDG_FAULT_MOUNT_COUNT="$case_dir/mount.count" \
      PDG_FAULT_MOUNT_FAIL_AT="$fail_at" \
      bash "$ROOT/tests/e2e-serial-hermetic.sh" \
      > "$case_dir/output.log" 2>&1; then
    die "serial helper accepted mount failure $fail_at"
  fi
  after="$(host_targets_fingerprint)" || die "cannot hash host after serial mount $fail_at"
  assert_failure_is_inert "$case_dir" "$before" "$after" "$case_dir/body.marker"
  IFS= read -r count < "$case_dir/mount.count"
  [[ "$count" -eq "$fail_at" ]] || die "serial helper continued after mount failure $fail_at"
  if grep -q '^串行顺序:' "$case_dir/output.log"; then
    die "serial body started after mount failure $fail_at"
  fi
  ok "serial mount failure $fail_at prevents all body and host writes"
}

validate_host_target_contract
run_fingerprint_contract
run_common_mktemp_failure
run_serial_mktemp_failure
run_serial_success_mktemp_cleanup
for failure in 1 2 3 4 5; do
  run_common_mount_failure "$failure"
  run_serial_mount_failure "$failure"
done

echo "OK: $pass overlay fault-injection cases passed"
[[ "$pass" -eq 14 ]]
