#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"
install_body="$(cat "${install}")"

first_three="$(head -c 3 "${install}" | od -An -tx1 | tr -d ' \n')"
if [[ "${first_three}" == "efbbbf" ]]; then
    echo "install.sh must not start with a UTF-8 BOM; it breaks the shebang when executed directly." >&2
    exit 1
fi

first_line="$(head -n 1 "${install}")"
if [[ "${first_line}" != "#!/usr/bin/env bash" && "${first_line}" != "#!/bin/bash" ]]; then
    echo "install.sh must start with a plain bash shebang." >&2
    exit 1
fi

if [[ "${install_body}" != *'systemd_unit_for_pid()'* ]]; then
    echo "install.sh must resolve the systemd unit that owns port 53 before stopping it." >&2
    exit 1
fi

if [[ "${install_body}" != *'systemd-resolved.service'* ]]; then
    echo "install.sh must handle systemd-resolved when it owns port 53 as systemd-resolve." >&2
    exit 1
fi

if [[ "${install_body}" != *'bootstrap_full_repo_if_needed'* ]]; then
    echo "install.sh must bootstrap the full repository when run as a single downloaded file." >&2
    exit 1
fi

if [[ "${install_body}" != *'https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz'* ]]; then
    echo "install.sh must know how to download the public repository tarball." >&2
    exit 1
fi

for required in dnsdist.conf.template sniproxy.conf update-rules.sh renew-hook.sh quic-proxy.go china-dns-race-proxy.go; do
    if [[ "${install_body}" != *"\"${required}\""* ]]; then
        echo "install.sh bootstrap must require ${required}." >&2
        exit 1
    fi
done

echo "install entrypoint policy OK"
