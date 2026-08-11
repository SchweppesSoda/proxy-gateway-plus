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

# These are the only host paths that either namespace entry may write after
# mounting.  Hash their exact contents before and after every injected failure.
host_targets_fingerprint(){
  local path digest
  for path in \
      /etc/gitconfig /etc/nftables.conf \
      /usr/local/bin/pdg /usr/local/libexec/pdg-quic-routing.sh \
      /opt/pdg-bot /opt/pdg-web /var/lib/privdns-gateway; do
    if [[ -L "$path" ]]; then
      printf 'link\t%s\t%s\n' "$path" "$(readlink "$path")"
    elif [[ -f "$path" ]]; then
      digest="$(sha256sum -- "$path" | awk '{print $1}')" || return 1
      printf 'file\t%s\t%s\n' "$path" "$digest"
    elif [[ -d "$path" ]]; then
      digest="$(tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
        -cf - -C "$path" . | sha256sum | awk '{print $1}')" || return 1
      printf 'dir\t%s\t%s\n' "$path" "$digest"
    elif [[ -e "$path" ]]; then
      printf 'other\t%s\t%s\n' "$path" "$(stat -c '%F:%a:%s' -- "$path")"
    else
      printf 'missing\t%s\n' "$path"
    fi
  done | sha256sum | awk '{print $1}'
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
      > "$case_dir/output.log" 2>&1; then
    die "serial helper accepted mktemp failure"
  fi
  after="$(host_targets_fingerprint)" || die "cannot hash host after serial mktemp case"
  assert_failure_is_inert "$case_dir" "$before" "$after" "$case_dir/body.marker"
  grep -q '^mktemp ' "$case_dir/calls.log" \
    || die "serial mktemp fault was not reached"
  if grep -q '^串行顺序:' "$case_dir/output.log"; then
    die "serial body started after mktemp failure"
  fi
  ok "serial helper fails closed when mktemp fails"
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

run_common_mktemp_failure
run_serial_mktemp_failure
for failure in 1 2 3 4 5; do
  run_common_mount_failure "$failure"
  run_serial_mount_failure "$failure"
done

echo "OK: $pass overlay fault-injection cases passed"
[[ "$pass" -eq 12 ]]
