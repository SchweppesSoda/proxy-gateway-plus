#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"
install_body="$(cat "${install}")"

require_marker() {
    local marker="$1"
    local description="$2"

    if [[ "${install_body}" != *"${marker}"* ]]; then
        echo "install.sh must ${description} (${marker})" >&2
        exit 1
    fi
}

require_marker 'BOOTSTRAP_SYSTEM_DNS=("1.1.1.1" "8.8.8.8" "9.9.9.9")' 'define bootstrap system resolvers'
require_marker 'resolv_conf_lacks_external_nameserver()' 'detect resolver files that only point at a local stub'
require_marker 'write_static_resolv_conf()' 'write a static /etc/resolv.conf when local DNS is being stopped'
require_marker 'ensure_system_dns_ready "$dns_probe_host" "apt dependency installation"' 'repair DNS before apt dependency installation'
require_marker 'ensure_system_dns_ready "$dns_probe_host" "reverse proxy dependency installation"' 'repair DNS before reverse proxy dependency installation'
require_marker 'ensure_resolver_survives_dns_owner_stop "$proc"' 'preserve system DNS before stopping the port 53 owner'

install_deps_line="$(grep -n '^[[:space:]]*install_deps$' "${install}" | head -n1 | cut -d: -f1)"
check_port_line="$(grep -n '^[[:space:]]*check_port_53$' "${install}" | head -n1 | cut -d: -f1)"

if [[ -z "${install_deps_line}" || -z "${check_port_line}" ]]; then
    echo "install.sh must call install_deps and check_port_53 from main_install." >&2
    exit 1
fi

if (( install_deps_line >= check_port_line )); then
    echo "main_install must install dependencies before stopping the local DNS service on port 53." >&2
    exit 1
fi

echo "system DNS bootstrap policy OK"
