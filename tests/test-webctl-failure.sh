#!/usr/bin/env bash
# Exercise the late-failure window after setup has already replaced web.json.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/etc" "$WORK/opt" "$WORK/bin"
printf 'OLD-CONFIG\n' >"$WORK/etc/web.json"
chmod 0600 "$WORK/etc/web.json"
printf '#!/usr/bin/env python3\n' >"$WORK/opt/setup.py"
chmod 0755 "$WORK/opt/setup.py"

sed \
  -e "s#CONFIG=/etc/privdns-gateway/web.json#CONFIG=$WORK/etc/web.json#" \
  -e "s#SETUP=/opt/pdg-web/pdg-web-setup.py#SETUP=$WORK/opt/setup.py#" \
  -e "s#UNIT=/etc/systemd/system/pdg-web.service#UNIT=$WORK/etc/pdg-web.service#" \
  -e "s#/etc/privdns-gateway/.web.json.#$WORK/etc/.web.json.#g" \
  -e 's/^need_root().*/need_root(){ :; }/' \
  "$ROOT/deploy/web/pdg-webctl.sh" >"$WORK/ctl.sh"
chmod 0755 "$WORK/ctl.sh"

cat >"$WORK/bin/python3" <<'SH'
#!/usr/bin/env bash
printf 'NEW-CONFIG\n' >"$TEST_CONFIG"
exit 2
SH
cat >"$WORK/bin/systemctl" <<'SH'
#!/usr/bin/env bash
case "$1" in
  is-active|restart|reset-failed) exit 0 ;;
  *) exit 0 ;;
esac
SH
cat >"$WORK/bin/install" <<'SH'
#!/usr/bin/env bash
src="${@: -2:1}"
dst="${@: -1}"
cp "$src" "$dst"
chmod 0600 "$dst"
SH
cat >"$WORK/bin/sleep" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod 0755 "$WORK/bin/"*

export TEST_CONFIG="$WORK/etc/web.json"
if PATH="$WORK/bin:$PATH" "$WORK/ctl.sh" setup >/dev/null 2>&1; then
  echo "[FAIL] late setup failure was reported as success" >&2
  exit 1
fi
grep -qxF OLD-CONFIG "$WORK/etc/web.json"
if compgen -G "$WORK/etc/.web.json.before.*" >/dev/null; then
  echo "[FAIL] successful recovery left a secret backup behind" >&2
  exit 1
fi

printf 'OLD-CONFIG\n' >"$WORK/etc/web.json"
# The setup executable is a disposable fault injector; recreate it for the
# independent second invocation.
printf '#!/usr/bin/env python3\n' >"$WORK/opt/setup.py"
chmod 0755 "$WORK/opt/setup.py"
cat >"$WORK/bin/systemctl" <<'SH'
#!/usr/bin/env bash
case "$1" in
  restart) exit 1 ;;
  is-active|reset-failed) exit 0 ;;
  *) exit 0 ;;
esac
SH
chmod 0755 "$WORK/bin/systemctl"
if PATH="$WORK/bin:$PATH" "$WORK/ctl.sh" setup >/dev/null 2>&1; then
  echo "[FAIL] failed restore was reported as success" >&2
  exit 1
fi
grep -qxF OLD-CONFIG "$WORK/etc/web.json"
mapfile -t evidence < <(compgen -G "$WORK/etc/.web.json.before.*")
if [[ "${#evidence[@]}" != 1 ]]; then
  echo "[FAIL] failed recovery did not retain exactly one backup" >&2
  exit 1
fi
evidence_mode="$(stat -c '%a' "${evidence[0]}")"
case "${OSTYPE:-}" in
  msys*|cygwin*) : ;;  # chmod metadata is not faithfully represented on NTFS
  *) [[ "$evidence_mode" == 600 ]] ;;
esac

printf '[Unit]\n' >"$WORK/etc/pdg-web.service"
cat >"$WORK/bin/python3" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat >"$WORK/bin/systemctl" <<'SH'
#!/usr/bin/env bash
case "$1" in
  enable)
    touch "$TEST_ENABLED_STATE"
    exit 1
    ;;
  disable)
    rm -f "$TEST_ENABLED_STATE"
    exit 0
    ;;
  is-enabled)
    [[ -f "$TEST_ENABLED_STATE" ]]
    ;;
  is-active) exit 1 ;;
  daemon-reload) exit 0 ;;
  *) exit 0 ;;
esac
SH
chmod 0755 "$WORK/bin/python3" "$WORK/bin/systemctl"
export TEST_ENABLED_STATE="$WORK/enabled"
if PATH="$WORK/bin:$PATH" "$WORK/ctl.sh" enable >/dev/null 2>&1; then
  echo "[FAIL] failed enable was reported as success" >&2
  exit 1
fi
[[ ! -e "$TEST_ENABLED_STATE" ]]

echo "[OK] pdg-webctl late setup recovery and failed-enable rollback"
