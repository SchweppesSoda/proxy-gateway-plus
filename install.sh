#!/usr/bin/env bash
#
# install.sh - High-performance transparent proxy + Smart DNS (DoT) one-click installer
# Supports: Ubuntu 20.04/22.04/24.04, Debian 11/12, CentOS 7/8/9 Stream,
#           Rocky Linux 8/9, AlmaLinux 8/9, RHEL 8/9, Fedora 39+
#

set -euo pipefail

# =============================================================================
# Configurable defaults
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_OWNER="SchweppesSoda"
REPO_NAME="proxy-gateway-plus"
REPO_BRANCH="${PROXY_GATEWAY_BRANCH:-main}"
REPO_ARCHIVE_URL="${PROXY_GATEWAY_ARCHIVE_URL:-https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz}"
BASE_DIR="/opt/proxy-gateway"
CONF_DIR="${BASE_DIR}/etc"
LOG_DIR="${BASE_DIR}/log"
SRC_DIR="${BASE_DIR}/src"
WWW_DIR="${BASE_DIR}/www"
IOS_PROFILE_PORT=8111
GFWLIST_URL="https://github.com/gfwlist/gfwlist/raw/master/gfwlist.txt"
CHINALIST_URL="https://github.com/felixonmars/dnsmasq-china-list/raw/master/accelerated-domains.china.conf"
CLOUDNS_FREE_TLDS=("abrdns.com" "cloud-ip.cc")
DEFAULT_OVERSEAS_DNS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
DEFAULT_PUBLIC_OVERSEAS_DNS=("1.1.1.1" "8.8.8.8")
DEFAULT_DNS_CACHE_SIZE=200000
DEFAULT_CLIENT_CIDR="172.22.0.0/16"
DEFAULT_SOCKS5_PORT=1080
DEFAULT_SOCKS5_USER="pgw"
DEFAULT_WG_PORT=51820
DEFAULT_WG_SERVER_ADDR="10.66.0.1/24"
DEFAULT_WG_CLIENT_ADDR="10.66.0.2/32"
REQUIRED_REPO_FILES=(
    "dnsdist.conf.template"
    "sniproxy.conf"
    "update-rules.sh"
    "renew-hook.sh"
    "quic-proxy.go"
    "china-dns-race-proxy.go"
)

# =============================================================================
# Colors
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERR]${NC}  $*" >&2; }

has_required_repo_files() {
    local file
    for file in "${REQUIRED_REPO_FILES[@]}"; do
        [[ -f "${SCRIPT_DIR}/${file}" ]] || return 1
    done
    return 0
}

download_repo_archive() {
    local output="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --connect-timeout 15 --retry 2 -o "$output" "$REPO_ARCHIVE_URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$output" "$REPO_ARCHIVE_URL"
    else
        err "curl or wget is required to download ${REPO_ARCHIVE_URL}"
        return 1
    fi
}

bootstrap_full_repo_if_needed() {
    has_required_repo_files && return 0

    if [[ "${PROXY_GATEWAY_BOOTSTRAPPED:-}" == "1" ]]; then
        err "Required repository files are still missing under ${SCRIPT_DIR}"
        exit 1
    fi
    if [[ "${PROXY_GATEWAY_NO_BOOTSTRAP:-}" == "1" ]]; then
        err "Required repository files are missing under ${SCRIPT_DIR}"
        exit 1
    fi
    if ! command -v tar >/dev/null 2>&1; then
        err "tar is required to extract ${REPO_ARCHIVE_URL}"
        exit 1
    fi

    local workdir archive extracted_dir
    workdir="$(mktemp -d "${TMPDIR:-/tmp}/${REPO_NAME}.XXXXXX")"
    archive="${workdir}/${REPO_NAME}.tar.gz"

    info "Current directory does not contain the full repository."
    info "Downloading ${REPO_ARCHIVE_URL}"
    download_repo_archive "$archive"
    tar -xzf "$archive" -C "$workdir"

    extracted_dir="$(find "$workdir" -mindepth 1 -maxdepth 1 -type d -name "${REPO_NAME}-*" | head -n 1 || true)"
    if [[ -z "$extracted_dir" || ! -f "${extracted_dir}/install.sh" ]]; then
        err "Failed to locate extracted ${REPO_NAME} repository under ${workdir}"
        exit 1
    fi

    chmod +x "${extracted_dir}/install.sh" "${extracted_dir}/update-rules.sh" "${extracted_dir}/renew-hook.sh" 2>/dev/null || true
    export PROXY_GATEWAY_BOOTSTRAPPED=1
    info "Switching to ${extracted_dir}/install.sh"
    exec "${extracted_dir}/install.sh" "$@"
}

tty_read() {
    local __var="$1"
    local prompt="$2"
    local default="${3:-}"
    local value=""

    if [[ -r /dev/tty ]]; then
        if [[ -n "$default" ]]; then
            printf "%s [%s]: " "$prompt" "$default" > /dev/tty
        else
            printf "%s: " "$prompt" > /dev/tty
        fi
        IFS= read -r value < /dev/tty || value=""
    elif [[ -t 0 ]]; then
        if [[ -n "$default" ]]; then
            printf "%s [%s]: " "$prompt" "$default"
        else
            printf "%s: " "$prompt"
        fi
        IFS= read -r value || value=""
    fi

    if [[ -z "$value" ]]; then
        value="$default"
    fi
    printf -v "$__var" '%s' "$value"
}

tty_yes_no() {
    local __var="$1"
    local prompt="$2"
    local default="${3:-Y}"
    local answer=""
    local suffix="[Y/n]"
    [[ "$default" =~ ^[Nn]$ ]] && suffix="[y/N]"

    while true; do
        tty_read answer "${prompt} ${suffix}" ""
        if [[ -z "$answer" ]]; then
            answer="$default"
        fi
        case "$answer" in
            y|Y|yes|YES) printf -v "$__var" '%s' "y"; return 0 ;;
            n|N|no|NO) printf -v "$__var" '%s' "n"; return 0 ;;
            *) warn "Invalid input, please enter y or n." ;;
        esac
    done
}

pause_return() {
    local _
    if [[ -r /dev/tty || -t 0 ]]; then
        tty_read _ "Press Enter to return" ""
    fi
}

random_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 18 | tr -d '=+/[:space:]' | cut -c1-24
    else
        tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 24
    fi
}

render_overseas_dns_servers() {
    local input="${1:-}"
    local pool="${2:-overseas}"
    local prefix="${3:-overseas}"
    local dns_list=()
    local item order=1 name

    if [[ -z "$input" ]]; then
        dns_list=("${DEFAULT_OVERSEAS_DNS[@]}")
    else
        input="${input//,/ }"
        read -r -a dns_list <<< "$input"
    fi

    for item in "${dns_list[@]}"; do
        [[ -z "$item" ]] && continue
        if [[ ! "$item" =~ ^[0-9A-Fa-f:.]+$ ]]; then
            warn "Skipping invalid overseas DNS address: $item"
            continue
        fi
        name="${prefix}${order}"
        printf 'newServer({address="%s:53", pool="%s", name="%s", order=%d, useClientSubnet=true})\n' "$item" "$pool" "$name" "$order"
        order=$((order + 1))
    done
}

render_sniproxy_dns_nameservers() {
    local input="${1:-}"
    local dns_list=()
    local item

    if [[ -z "$input" ]]; then
        dns_list=("${DEFAULT_OVERSEAS_DNS[@]}")
    else
        input="${input//,/ }"
        read -r -a dns_list <<< "$input"
    fi

    for item in "${dns_list[@]}"; do
        [[ -z "$item" ]] && continue
        if [[ ! "$item" =~ ^[0-9A-Fa-f:.]+$ ]]; then
            warn "Skipping invalid sniproxy DNS address: $item"
            continue
        fi
        printf '    nameserver %s\n' "$item"
    done
}

configure_overseas_dns() {
    local legacy="${OVERSEAS_DNS:-}"
    local private_selected="${PRIVATE_OVERSEAS_DNS:-$legacy}"
    local public_selected="${PUBLIC_OVERSEAS_DNS:-}"
    local sniproxy_selected="${SNIPROXY_DNS:-}"

    if [[ -z "$private_selected" && -t 0 ]]; then
        echo ""
        tty_read private_selected "Private overseas DNS upstreams" "1.1.1.1,8.8.8.8,9.9.9.9"
    fi
    if [[ -z "$public_selected" && -t 0 ]]; then
        tty_read public_selected "Public overseas DNS upstreams" "1.1.1.1,8.8.8.8"
    fi
    if [[ -z "$sniproxy_selected" && -t 0 ]]; then
        tty_read sniproxy_selected "sniproxy resolver upstreams" ""
    fi

    if [[ -z "$private_selected" ]]; then
        private_selected="${DEFAULT_OVERSEAS_DNS[*]}"
    fi
    if [[ -z "$public_selected" ]]; then
        public_selected="${DEFAULT_PUBLIC_OVERSEAS_DNS[*]}"
    fi
    if [[ -z "$sniproxy_selected" ]]; then
        sniproxy_selected="$private_selected"
    fi

    OVERSEAS_DNS="$private_selected"
    PRIVATE_OVERSEAS_DNS="$private_selected"
    PUBLIC_OVERSEAS_DNS="$public_selected"
    SNIPROXY_DNS="$sniproxy_selected"

    mkdir -p "$CONF_DIR"
    echo "$PRIVATE_OVERSEAS_DNS" > "${CONF_DIR}/.overseas_dns"
    echo "$PRIVATE_OVERSEAS_DNS" > "${CONF_DIR}/.overseas_private_dns"
    echo "$PUBLIC_OVERSEAS_DNS" > "${CONF_DIR}/.overseas_public_dns"
    echo "$SNIPROXY_DNS" > "${CONF_DIR}/.sniproxy_dns"
    info "Private overseas DNS upstreams: $PRIVATE_OVERSEAS_DNS"
    info "Public overseas DNS upstreams: $PUBLIC_OVERSEAS_DNS"
    info "sniproxy resolver upstreams: $SNIPROXY_DNS"
}

valid_domain() {
    local domain="$1"
    domain="${domain%%#*}"
    domain="${domain%.}"
    domain="${domain#www.}"
    [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?)+$ ]]
}

configure_dns_policy() {
    check_root
    local other_policy="${OTHER_POLICY:-}"
    local cache_size="${DNS_CACHE_SIZE:-}"
    local choice=""

    mkdir -p "$CONF_DIR"

    echo ""
    echo "=================================================="
    echo "  DNS 分流策略"
    echo "=================================================="
    echo "  1) 其他域名默认直连"
    echo "  2) 其他域名默认走 VPS1 SNI/QUIC 代理"
    echo "=================================================="
    while true; do
        if [[ "$other_policy" == "proxy" ]]; then
            choice="2"
        elif [[ "$other_policy" == "direct" ]]; then
            choice="1"
        else
            tty_read choice "请输入序号 (1-2)" "1"
        fi
        case "$choice" in
            1) other_policy="direct"; break ;;
            2) other_policy="proxy"; break ;;
            *) warn "无效输入，请重新输入 1-2 之间的数字" ;;
        esac
    done
    echo "$other_policy" > "${CONF_DIR}/.other_policy"
    if [[ -d /etc/dnsdist ]]; then
        echo "$other_policy" > /etc/dnsdist/.other_policy
    fi
    OTHER_POLICY="$other_policy"

    echo ""
    echo "=================================================="
    echo "  dnsdist 缓存大小"
    echo "=================================================="
    echo "  1) 50000"
    echo "  2) 100000"
    echo "  3) 200000"
    echo "  4) 500000"
    echo "  5) 自定义"
    echo "=================================================="
    while true; do
        if [[ -n "$cache_size" ]]; then
            choice="custom"
        else
            tty_read choice "请输入序号 (1-5)" "3"
        fi
        case "$choice" in
            1) cache_size=50000; break ;;
            2) cache_size=100000; break ;;
            3) cache_size=$DEFAULT_DNS_CACHE_SIZE; break ;;
            4) cache_size=500000; break ;;
            5|custom)
                tty_read cache_size "请输入 dnsdist cache 条目数" "${cache_size:-$DEFAULT_DNS_CACHE_SIZE}"
                if [[ "$cache_size" =~ ^[0-9]+$ && "$cache_size" -gt 0 ]]; then
                    break
                fi
                warn "无效输入，请输入正整数"
                cache_size=""
                ;;
            *) warn "无效输入，请重新输入 1-5 之间的数字" ;;
        esac
    done
    echo "$cache_size" > "${CONF_DIR}/.cache_size"
    if [[ -d /etc/dnsdist ]]; then
        echo "$cache_size" > /etc/dnsdist/.cache_size
    fi
    DNS_CACHE_SIZE="$cache_size"

    touch "${CONF_DIR}/proxy-extra-local.txt" \
        "${CONF_DIR}/direct-extra-local.txt" \
        "${CONF_DIR}/custom-proxy-lists.txt" \
        "${CONF_DIR}/custom-direct-lists.txt"
    if [[ -d /etc/dnsdist ]]; then
        touch /etc/dnsdist/proxy-extra-local.txt \
            /etc/dnsdist/direct-extra-local.txt \
            /etc/dnsdist/custom-proxy-lists.txt \
            /etc/dnsdist/custom-direct-lists.txt
    fi
    ok "DNS policy saved (other: ${OTHER_POLICY}, cache: ${DNS_CACHE_SIZE})"
}

append_line_if_missing() {
    local file="$1"
    local value="$2"
    mkdir -p "$(dirname "$file")"
    touch "$file"
    if ! grep -Fxq "$value" "$file"; then
        printf '%s\n' "$value" >> "$file"
    fi
}

configure_custom_lists_menu() {
    check_root
    local choice="" value="" file=""
    local policy_dir="$CONF_DIR"
    [[ -d /etc/dnsdist ]] && policy_dir="/etc/dnsdist"
    mkdir -p "$policy_dir"

    while true; do
        echo ""
        echo "=================================================="
        echo "  自定义分流列表"
        echo "=================================================="
        echo "  1) 添加走代理的远程 list URL"
        echo "  2) 添加直连的远程 list URL"
        echo "  3) 添加本地代理域名"
        echo "  4) 添加本地直连域名"
        echo "  5) 查看当前列表"
        echo "  0) 返回主菜单"
        echo "=================================================="
        tty_read choice "请输入序号 (0-5)" ""
        case "$choice" in
            1)
                tty_read value "远程 proxy list URL" ""
                [[ -z "$value" ]] && warn "URL 不能为空" && continue
                append_line_if_missing "${policy_dir}/custom-proxy-lists.txt" "$value"
                ok "已添加 proxy list: $value"
                ;;
            2)
                tty_read value "远程 direct list URL" ""
                [[ -z "$value" ]] && warn "URL 不能为空" && continue
                append_line_if_missing "${policy_dir}/custom-direct-lists.txt" "$value"
                ok "已添加 direct list: $value"
                ;;
            3)
                tty_read value "代理域名" ""
                valid_domain "$value" || { warn "无效域名: $value"; continue; }
                append_line_if_missing "${policy_dir}/proxy-extra-local.txt" "$value"
                ok "已添加代理域名: $value"
                ;;
            4)
                tty_read value "直连域名" ""
                valid_domain "$value" || { warn "无效域名: $value"; continue; }
                append_line_if_missing "${policy_dir}/direct-extra-local.txt" "$value"
                ok "已添加直连域名: $value"
                ;;
            5)
                for file in proxy-extra-local.txt direct-extra-local.txt custom-proxy-lists.txt custom-direct-lists.txt; do
                    echo ""
                    echo "== ${policy_dir}/${file} =="
                    if [[ -s "${policy_dir}/${file}" ]]; then
                        sed -n '1,120p' "${policy_dir}/${file}"
                    else
                        echo "(empty)"
                    fi
                done
                pause_return
                ;;
            0) return 0 ;;
            *) warn "无效输入，请重新输入 0-5 之间的数字" ;;
        esac
    done
}

# =============================================================================
# Command-line dispatch
# =============================================================================
usage() {
    cat <<EOF
Usage: $0 [OPTION]

Options:
  (none)         Full interactive installation
  --status       Show service status
  --update-rules Update GFWList/ChinaList and reload dnsdist
  --renew-cert   Force renew certificates and reload services
  --uninstall    Remove all installed components
  -ios          Regenerate iOS DoT profile and QR code
  -h, --help     Show this help

Environment variables (for non-interactive use):
  DOMAIN         Pre-configured domain (skip ClouDNS registration)
  OVERSEAS_DNS   Backward-compatible alias for PRIVATE_OVERSEAS_DNS
  PRIVATE_OVERSEAS_DNS  Overseas upstream DNS for 172.22.0.0/16 DoT clients
  PUBLIC_OVERSEAS_DNS   Overseas upstream DNS for non-private DoT clients
  SNIPROXY_DNS   Resolver upstream DNS for TCP sniproxy backends
  CLOUDNS_ID     ClouDNS API auth-id
  CLOUDNS_PASS   ClouDNS API auth-password
  EMAIL          Email for Let's Encrypt
EOF
}

# =============================================================================
# Basic checks
# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        err "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    case "$OS" in
        ubuntu|debian)
            PKG_MGR="apt-get"
            ;;
        centos|rhel|rocky|almalinux|fedora)
            if command -v dnf >/dev/null 2>&1; then
                PKG_MGR="dnf"
            else
                PKG_MGR="yum"
            fi
            ;;
        *)
            err "Unsupported OS: $OS"
            exit 1
            ;;
    esac

    info "Detected OS: $OS $VER (package manager: $PKG_MGR)"
}

get_public_ip() {
    PUBLIC_IP=$(curl -4 -s --max-time 10 https://api.ipify.org 2>/dev/null || \
                curl -4 -s --max-time 10 https://ifconfig.me 2>/dev/null || \
                curl -4 -s --max-time 10 https://icanhazip.com 2>/dev/null || echo "")
    if [[ -z "$PUBLIC_IP" ]]; then
        PUBLIC_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+' || echo "")
    fi
    if [[ -z "$PUBLIC_IP" ]]; then
        err "Failed to detect public IPv4 address. Please set PUBLIC_IP manually."
        exit 1
    fi
    info "Public IP detected: $PUBLIC_IP"
}

check_port_53() {
    info "Checking port 53 availability..."
    local pid
    pid=$(ss -lnptu 2>/dev/null | grep ':53 ' | head -n1 | grep -oP 'pid=\K[0-9]+' || true)

    if [[ -n "$pid" ]]; then
        local proc
        proc=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        warn "Port 53 is already in use by: $proc (PID: $pid)"

        tty_read confirm "Stop and disable '$proc' to free port 53? [Y/n]" ""
        if [[ "$confirm" =~ ^[Nn]$ ]]; then
            err "Port 53 must be free for dnsdist to start. Aborting."
            exit 1
        fi

        stop_port53_owner "$pid" "$proc"
        sleep 1

        # Double check
        pid=$(ss -lnptu 2>/dev/null | grep ':53 ' | head -n1 | grep -oP 'pid=\K[0-9]+' || true)
        if [[ -n "$pid" ]]; then
            err "Failed to free port 53. Please manually stop the service using it."
            exit 1
        fi
        ok "Port 53 is now free"
    else
        ok "Port 53 is available"
    fi
}

systemd_unit_for_pid() {
    local pid="${1:-}"
    [[ -z "$pid" || ! -r "/proc/$pid/cgroup" ]] && return 0
    grep -aoE '[^/]+\.service' "/proc/$pid/cgroup" | head -n1 || true
}

stop_port53_owner() {
    local pid="${1:-}"
    local proc="${2:-unknown}"
    local unit
    unit=$(systemd_unit_for_pid "$pid")

    if [[ -n "$unit" ]]; then
        info "Stopping systemd unit owning port 53: $unit"
        systemctl stop "$unit" 2>/dev/null || true
        systemctl disable "$unit" 2>/dev/null || true
    fi

    case "$proc" in
        systemd-resolve|systemd-resolved)
            info "Stopping systemd-resolved service to release DNS stub port 53"
            systemctl stop systemd-resolved.service 2>/dev/null || true
            systemctl disable systemd-resolved.service 2>/dev/null || true
            ;;
        dnsmasq)
            systemctl stop dnsmasq.service 2>/dev/null || true
            systemctl disable dnsmasq.service 2>/dev/null || true
            ;;
        named)
            systemctl stop named.service bind9.service 2>/dev/null || true
            systemctl disable named.service bind9.service 2>/dev/null || true
            ;;
    esac

    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
    fi
}

# =============================================================================
# Dependencies
# =============================================================================
install_deps() {
    info "Installing system dependencies..."

    case "$PKG_MGR" in
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq \
                build-essential git wget curl ca-certificates \
                libev-dev libpcre3-dev libudns-dev libssl-dev \
                autoconf automake libtool pkg-config \
                dnsdist certbot python3-certbot-dns-cloudflare \
                python3 python3-pip jq libcap2-bin \
                nftables qrencode || true
            ;;
        dnf|yum)
            $PKG_MGR install -y -q \
                gcc gcc-c++ make git wget curl ca-certificates \
                libev-devel pcre-devel openssl-devel \
                autoconf automake libtool pkgconfig \
                dnsdist certbot python3-certbot-dns-cloudflare \
                python3 python3-pip jq libcap-ng-utils \
                nftables qrencode || true
            ;;
    esac

    # Ensure Go is installed (for quic-proxy compilation)
    if ! command -v go >/dev/null 2>&1; then
        info "Installing Go compiler..."
        GO_VER="1.22.4"
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64) GO_ARCH="amd64" ;;
            aarch64|arm64) GO_ARCH="arm64" ;;
            *) GO_ARCH="amd64" ;;
        esac
        wget -q "https://go.dev/dl/go${GO_VER}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
    fi

    ok "Go version: $(go version)"

    # Ensure Python requests for cloudns API fallback
    pip3 install requests -q 2>/dev/null || true

    # Fix certbot compatibility on newer Python versions (e.g. 3.12+)
    if command -v certbot >/dev/null 2>&1; then
        if ! certbot --version >/dev/null 2>&1; then
            warn "Certbot has compatibility issues with the current Python version. Attempting to fix..."
            pip3 install --upgrade --break-system-packages certbot josepy cryptography 2>/dev/null || \
                pip3 install --upgrade certbot josepy cryptography 2>/dev/null || true
        fi
    fi

    # Verify critical binaries
    for bin in dnsdist certbot; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            err "Required package '$bin' was not installed successfully."
            err "Please check your package manager output above."
            exit 1
        fi
    done
}

# =============================================================================
# Domain generation & ClouDNS
# =============================================================================
generate_domain() {
    if [[ -n "${DOMAIN:-}" ]]; then
        info "Using pre-configured domain: $DOMAIN"
        DOMAIN_PRECONFIGURED=1
        mkdir -p "$CONF_DIR"
        echo "$DOMAIN" > "${CONF_DIR}/.domain"
        return
    fi

    # Generate a deterministic 4-char lowercase alphabetic prefix from IP hash
    # Same IP always produces the same prefix, keeping reinstalls consistent
    local prefix
    prefix=$(python3 -c "
import hashlib
h = hashlib.md5('${PUBLIC_IP}'.encode()).hexdigest()[:4]
print(''.join(chr(97 + int(c, 16) % 26) for c in h))
")

    local tld=""

    # If TLD is preset via environment variable, use it directly
    if [[ -n "${CLOUDNS_TLD:-}" ]]; then
        tld="${CLOUDNS_TLD}"
        info "Using pre-selected TLD: ${tld}"
    else
        # Interactive selection
        echo ""
        echo "=================================================="
        echo "  请选择 ClouDNS 免费域名后缀"
        echo "=================================================="
        local i=1
        for t in "${CLOUDNS_FREE_TLDS[@]}"; do
            echo "  ${i}) ${prefix}.${t}"
            i=$((i + 1))
        done
        echo "=================================================="
        echo ""

        local choice=""
        while true; do
            tty_read choice "请输入序号 (1-${#CLOUDNS_FREE_TLDS[@]})" ""
            if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#CLOUDNS_FREE_TLDS[@]} ]]; then
                tld="${CLOUDNS_FREE_TLDS[$((choice - 1))]}"
                break
            else
                warn "无效输入，请重新输入 1-${#CLOUDNS_FREE_TLDS[@]} 之间的数字"
            fi
        done
    fi

    DOMAIN="${prefix}.${tld}"

    info "Generated混淆域名: $DOMAIN"
    info "Prefix is derived from public IP (same IP = same prefix)"

    # Always update domain file so reinstalls pick up the current choice
    mkdir -p "$CONF_DIR"
    echo "$DOMAIN" > "${CONF_DIR}/.domain"
}

register_domain_cloudns() {
    if [[ "${DOMAIN_PRECONFIGURED:-0}" == "1" ]]; then
        info "Skipping ClouDNS registration prompt for pre-configured domain: $DOMAIN"
        mkdir -p "$CONF_DIR"
        echo "$DOMAIN" > "${CONF_DIR}/.domain"
        return
    fi

    if [[ -f "${CONF_DIR}/.domain_registered" ]]; then
        info "Domain already registered flag found."
        # Ensure .domain file stays in sync even on reinstalls
        local saved_domain=""
        saved_domain=$(cat "${CONF_DIR}/.domain" 2>/dev/null || true)
        if [[ "$saved_domain" != "$DOMAIN" ]]; then
            warn "Updating saved domain: $saved_domain -> $DOMAIN"
            echo "$DOMAIN" > "${CONF_DIR}/.domain"
        fi
        return
    fi

    info "ClouDNS 注册提示"
    info "=================================================="
    info "域名: $DOMAIN"
    info "A 记录值: $PUBLIC_IP"
    info "=================================================="
    info ""
    info "请按以下步骤完成注册（免费）:"
    info "1. 访问 https://www.cloudns.net 并登录/注册免费账户"
    info "2. 进入 Dashboard -> Create zone -> Free zone"
    info "3. 输入域名前缀: ${DOMAIN%%.*}"
    info "4. 选择后缀: .${DOMAIN##*.}"
    info "5. 创建后添加一条 A 记录:"
    info "   Host: @ (或留空)"
    info "   Type: A"
    info "   Points to: $PUBLIC_IP"
    info "   TTL: 3600"
    info ""

    # Try API registration if credentials provided
    if [[ -n "${CLOUDNS_ID:-}" && -n "${CLOUDNS_PASS:-}" ]]; then
        info "尝试通过 ClouDNS API 自动注册..."
        local resp
        resp=$(curl -s -X POST "https://api.cloudns.net/dns/register.json" \
            -d "auth-id=${CLOUDNS_ID}" \
            -d "auth-password=${CLOUDNS_PASS}" \
            -d "domain-name=${DOMAIN}" \
            -d "zone-type=domain" 2>/dev/null || echo "")
        if echo "$resp" | grep -qi "success\|registered"; then
            ok "API 注册成功 (或域名已存在)"
            sleep 2
            # Add A record
            curl -s -X POST "https://api.cloudns.net/dns/add-record.json" \
                -d "auth-id=${CLOUDNS_ID}" \
                -d "auth-password=${CLOUDNS_PASS}" \
                -d "domain-name=${DOMAIN}" \
                -d "record-type=A" \
                -d "host=" \
                -d "record=${PUBLIC_IP}" \
                -d "ttl=3600" >/dev/null || true
            mkdir -p "$CONF_DIR"
            echo "$DOMAIN" > "${CONF_DIR}/.domain"
            touch "${CONF_DIR}/.domain_registered"
            return
        else
            warn "API 注册失败或不可用 ($resp)，请手动注册"
        fi
    fi

    info ""
    tty_read confirm "完成注册后按 Enter 继续（或输入 'skip' 跳过验证）" ""
    if [[ "$confirm" == "skip" ]]; then
        warn "跳过域名解析验证，请确保 A 记录已正确配置"
    else
        info "等待 DNS 解析生效（最多 120 秒）..."
        local waited=0
        while [[ $waited -lt 120 ]]; do
            local resolved
            resolved=$(dig +short "$DOMAIN" @1.1.1.1 2>/dev/null || echo "")
            if [[ "$resolved" == "$PUBLIC_IP" ]]; then
                ok "DNS 解析验证通过: $DOMAIN -> $PUBLIC_IP"
                break
            fi
            sleep 5
            waited=$((waited + 5))
            echo -n "."
        done
        if [[ $waited -ge 120 ]]; then
            warn "DNS 解析未在 120 秒内生效，将继续安装。如后续证书申请失败，请检查 DNS 配置。"
        fi
    fi

    mkdir -p "$CONF_DIR"
    echo "$DOMAIN" > "${CONF_DIR}/.domain"
    touch "${CONF_DIR}/.domain_registered"
}

# =============================================================================
# Let's Encrypt Certificate
# =============================================================================
install_cert() {
    local certbot_cmd certbot_cmd_force
    install_certbot_firewall_hooks

    # Normal issuance (first time) - no force-renewal to avoid rate limits
    certbot_cmd=(certbot certonly --standalone -d "$DOMAIN" \
        --agree-tos -n -m "${EMAIL:-admin@${DOMAIN}}" \
        --pre-hook /usr/local/bin/proxy-gateway-open-cert-http.sh \
        --post-hook /usr/local/bin/proxy-gateway-restore-firewall.sh)
    # Reinstall / explicit renew - force renewal
    certbot_cmd_force=(certbot certonly --standalone -d "$DOMAIN" --force-renewal \
        --agree-tos -n -m "${EMAIL:-admin@${DOMAIN}}" \
        --pre-hook /usr/local/bin/proxy-gateway-open-cert-http.sh \
        --post-hook /usr/local/bin/proxy-gateway-restore-firewall.sh)

    local cb_cmd=()
    if [[ -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
        info "Let's Encrypt certificate already exists for $DOMAIN, forcing renewal..."
        cb_cmd=("${certbot_cmd_force[@]}")
    else
        info "申请 Let's Encrypt 证书 for $DOMAIN..."
        cb_cmd=("${certbot_cmd[@]}")
    fi

    run_certbot() {
        open_cert_http_port
        trap restore_reverse_proxy_firewall RETURN
        if "${cb_cmd[@]}"; then
            return 0
        fi
        # Check for known Python compatibility error
        if "${cb_cmd[@]}" 2>&1 | grep -q "AttributeError" || \
           certbot --version 2>&1 | grep -q "AttributeError"; then
            warn "Certbot compatibility error detected. Attempting to fix Python dependencies..."
            pip3 install --upgrade --break-system-packages certbot josepy cryptography 2>/dev/null || \
                pip3 install --upgrade certbot josepy cryptography 2>/dev/null || true
            info "Retrying certificate request..."
            "${cb_cmd[@]}"
        else
            return 1
        fi
    }

    if ! run_certbot; then
        err "证书申请失败。请检查:"
        err "  1. 域名 $DOMAIN 是否正确解析到本机 ($PUBLIC_IP)"
        err "  2. 端口 80 是否被占用"
        err "  3. 防火墙是否放行 80"
        err "  4. 是否触发了 Let's Encrypt 速率限制 (同一域名 7 天内限 5 次)"
        exit 1
    fi

    # Copy certificates to dnsdist-readable location
    info "Copying certificates to /etc/dnsdist/certs/ ..."
    local cert_live_dir="/etc/letsencrypt/live/${DOMAIN}"
    if [[ -d "$cert_live_dir" ]]; then
        mkdir -p /etc/dnsdist/certs
        cp "${cert_live_dir}/fullchain.pem" /etc/dnsdist/certs/fullchain.pem
        cp "${cert_live_dir}/privkey.pem" /etc/dnsdist/certs/privkey.pem
        chown -R _dnsdist:_dnsdist /etc/dnsdist/certs/
        chmod 640 /etc/dnsdist/certs/*.pem
        ok "Certificates copied to /etc/dnsdist/certs/"
    else
        warn "Could not find certificate live directory: $cert_live_dir"
    fi

    # Deploy renewal hook (also handles cert copy on renewal)
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cp "${SCRIPT_DIR}/renew-hook.sh" /etc/letsencrypt/renewal-hooks/deploy/99-reload-dnsdist.sh
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/99-reload-dnsdist.sh
    ok "证书已就绪，自动续期 Hook 已部署"
}

# =============================================================================
# sniproxy (TCP)
# =============================================================================
install_sniproxy() {
    if ! command -v sniproxy >/dev/null 2>&1; then
        info "Compiling sniproxy (TCP SNI proxy)..."
        mkdir -p "$SRC_DIR"
        cd "$SRC_DIR"

        if [[ ! -d sniproxy ]]; then
            git clone --depth=1 https://github.com/dlundquist/sniproxy.git
        fi
        cd sniproxy

        DEBEMAIL="root@localhost" DEBFULLNAME="root" ./autogen.sh >/dev/null
        ./configure --prefix=/usr/local --sysconfdir=/etc --enable-dns >/dev/null
        make -j$(nproc) >/dev/null
        make install >/dev/null
    else
        info "sniproxy already installed"
    fi

    if [[ -f "${SCRIPT_DIR}/sniproxy.conf" ]]; then
        local sniproxy_nameservers
        sniproxy_nameservers=$(render_sniproxy_dns_nameservers "$SNIPROXY_DNS")
        python3 - "${SCRIPT_DIR}/sniproxy.conf" "$sniproxy_nameservers" /etc/sniproxy.conf <<'PYEOF'
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    content = f.read()
content = content.replace("__SNIPROXY_NAMESERVERS__", sys.argv[2])
with open(sys.argv[3], "w", encoding="utf-8") as f:
    f.write(content)
PYEOF
    else
        err "sniproxy.conf not found in ${SCRIPT_DIR}"
        exit 1
    fi

    # systemd service
    cat > /etc/systemd/system/sniproxy.service <<'EOF'
[Unit]
Description=sniproxy (TCP SNI transparent proxy)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/sniproxy -c /etc/sniproxy.conf -f
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sniproxy
    ok "sniproxy installed"
}

# =============================================================================
# quic-proxy (UDP / QUIC SNI proxy)
# =============================================================================
install_quic_proxy() {
    if [[ ! -x "${BASE_DIR}/bin/quic-proxy" ]]; then
        info "Compiling quic-proxy (UDP/QUIC SNI proxy)..."
        mkdir -p "${BASE_DIR}/bin"
        mkdir -p "${SRC_DIR}"
        cp "${SCRIPT_DIR}/quic-proxy.go" "${SRC_DIR}/quic-proxy.go"
        cd "${SRC_DIR}"

        export PATH=$PATH:/usr/local/go/bin
        go build -ldflags="-s -w" -o "${BASE_DIR}/bin/quic-proxy" quic-proxy.go
    else
        info "quic-proxy already compiled"
    fi

    # systemd service
    cat > /etc/systemd/system/quic-proxy.service <<'EOF'
[Unit]
Description=quic-proxy (UDP/QUIC SNI transparent proxy)
After=network.target

[Service]
Type=simple
ExecStart=/opt/proxy-gateway/bin/quic-proxy -l 0.0.0.0:443
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=root
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable quic-proxy
    ok "quic-proxy installed"
}

# =============================================================================
# China DNS race proxy (UDP DNS upstream racing for ChinaList)
# =============================================================================
install_china_dns_race_proxy() {
    info "Compiling china-dns-race-proxy..."
    mkdir -p "${BASE_DIR}/bin"
    mkdir -p "${SRC_DIR}"
    cp "${SCRIPT_DIR}/china-dns-race-proxy.go" "${SRC_DIR}/china-dns-race-proxy.go"
    cd "${SRC_DIR}"

    export PATH=$PATH:/usr/local/go/bin
    go build -ldflags="-s -w" -o "${BASE_DIR}/bin/china-dns-race-proxy" china-dns-race-proxy.go

    cat > /etc/systemd/system/china-dns-race-proxy.service <<'EOF'
[Unit]
Description=China DNS race proxy
After=network.target
Before=dnsdist.service

[Service]
Type=simple
ExecStart=/opt/proxy-gateway/bin/china-dns-race-proxy -l 127.0.0.1:5301
Restart=on-failure
RestartSec=3
User=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable china-dns-race-proxy
    ok "china-dns-race-proxy installed"
}

# =============================================================================
# dnsdist (DoT + Smart DNS)
# =============================================================================
install_dnsdist() {
    info "Configuring dnsdist..."

    mkdir -p /etc/dnsdist
    cp "${SCRIPT_DIR}/dnsdist.conf.template" /etc/dnsdist/dnsdist.conf.template
    cp "${SCRIPT_DIR}/update-rules.sh" /usr/local/bin/update-dnsdist-rules.sh
    chmod +x /usr/local/bin/update-dnsdist-rules.sh

    # Save domain and IP for template generation
    echo "$DOMAIN" > /etc/dnsdist/.domain
    echo "$PUBLIC_IP" > /etc/dnsdist/.public_ip
    echo "$PRIVATE_OVERSEAS_DNS" > /etc/dnsdist/.overseas_dns
    echo "$PRIVATE_OVERSEAS_DNS" > /etc/dnsdist/.overseas_private_dns
    echo "$PUBLIC_OVERSEAS_DNS" > /etc/dnsdist/.overseas_public_dns
    echo "$SNIPROXY_DNS" > /etc/dnsdist/.sniproxy_dns
    echo "${OTHER_POLICY:-direct}" > /etc/dnsdist/.other_policy
    echo "${DNS_CACHE_SIZE:-$DEFAULT_DNS_CACHE_SIZE}" > /etc/dnsdist/.cache_size
    touch /etc/dnsdist/proxy-extra-local.txt \
        /etc/dnsdist/direct-extra-local.txt \
        /etc/dnsdist/custom-proxy-lists.txt \
        /etc/dnsdist/custom-direct-lists.txt
    local policy_file
    for policy_file in proxy-extra-local.txt direct-extra-local.txt custom-proxy-lists.txt custom-direct-lists.txt; do
        if [[ -s "${CONF_DIR}/${policy_file}" && ! -s "/etc/dnsdist/${policy_file}" ]]; then
            cp "${CONF_DIR}/${policy_file}" "/etc/dnsdist/${policy_file}"
        fi
    done
    local overseas_private_servers overseas_public_servers
    overseas_private_servers=$(render_overseas_dns_servers "$PRIVATE_OVERSEAS_DNS" "overseas_private" "overseas_private")
    overseas_public_servers=$(render_overseas_dns_servers "$PUBLIC_OVERSEAS_DNS" "overseas_public" "overseas_public")

    # Determine actual certificate directory name
    local cert_basename="${DOMAIN}"
    if [[ -f "${CONF_DIR}/.cert_basename" ]]; then
        cert_basename=$(cat "${CONF_DIR}/.cert_basename")
    fi

    # Generate initial config (empty rules, will be populated by update-rules.sh)
    python3 - /etc/dnsdist/dnsdist.conf.template "${PUBLIC_IP}" "${cert_basename}" "$overseas_private_servers" "$overseas_public_servers" "${OTHER_POLICY:-direct}" "${DNS_CACHE_SIZE:-$DEFAULT_DNS_CACHE_SIZE}" /etc/dnsdist/dnsdist.conf <<'PYEOF'
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    content = f.read()
content = content.replace("__GFWLIST_RULES__", "-- (rules will be loaded by update-rules.sh)")
content = content.replace("__CHINALIST_RULES__", "-- (rules will be loaded by update-rules.sh)")
content = content.replace("__PROXY_EXTRA_RULES__", "-- (rules will be loaded by update-rules.sh)")
content = content.replace("__DIRECT_EXTRA_RULES__", "-- (rules will be loaded by update-rules.sh)")
content = content.replace("__SERVER_IP__", sys.argv[2])
content = content.replace("__DOMAIN__", sys.argv[3])
content = content.replace("__OVERSEAS_PRIVATE_DNS_SERVERS__", sys.argv[4])
content = content.replace("__OVERSEAS_PUBLIC_DNS_SERVERS__", sys.argv[5])
content = content.replace("__OTHER_POLICY__", sys.argv[6])
content = content.replace("__DNS_CACHE_SIZE__", sys.argv[7])
with open(sys.argv[8], "w", encoding="utf-8") as f:
    f.write(content)
PYEOF

    # systemd override for dnsdist (ensure it reads our config + supports reload)
    mkdir -p /etc/systemd/system/dnsdist.service.d
    cat > /etc/systemd/system/dnsdist.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/dnsdist --supervised -C /etc/dnsdist/dnsdist.conf
ExecReload=/bin/kill -HUP $MAINPID
LimitNOFILE=65535
EOF

    systemctl daemon-reload
    systemctl enable dnsdist
    ok "dnsdist configured"
}

# =============================================================================
# Rules initialization
# =============================================================================
init_rules() {
    info "Initializing GFWList and ChinaList..."
    /usr/local/bin/update-dnsdist-rules.sh || warn "Rule update failed, will retry later"
}

# =============================================================================
# iOS DoT profile
# =============================================================================
generate_ios_profile() {
    info "Generating iOS DoT configuration profile..."

    mkdir -p "$WWW_DIR"
    local profile_path="${WWW_DIR}/ios-dot.mobileconfig"
    local profile_url="http://${DOMAIN}:${IOS_PROFILE_PORT}/ios-dot.mobileconfig"

    cat > "$profile_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>TLS</string>
                <key>ServerName</key>
                <string>${DOMAIN}</string>
                <key>ServerAddresses</key>
                <array>
                    <string>${PUBLIC_IP}</string>
                </array>
            </dict>
            <key>OnDemandRules</key>
            <array>
                <dict>
                    <key>Action</key>
                    <string>Connect</string>
                    <key>InterfaceTypeMatch</key>
                    <string>Cellular</string>
                </dict>
                <dict>
                    <key>Action</key>
                    <string>Disconnect</string>
                    <key>InterfaceTypeMatch</key>
                    <string>WiFi</string>
                </dict>
                <dict>
                    <key>Action</key>
                    <string>Disconnect</string>
                </dict>
            </array>
            <key>PayloadDescription</key>
            <string>Use ${DOMAIN} DNS over TLS only on cellular networks.</string>
            <key>PayloadDisplayName</key>
            <string>Proxy Gateway Cellular DoT</string>
            <key>PayloadIdentifier</key>
            <string>com.proxy-gateway.${DOMAIN}.dnssettings</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Installs a DNS over TLS profile for cellular networks only.</string>
    <key>PayloadDisplayName</key>
    <string>Proxy Gateway Cellular DoT</string>
    <key>PayloadIdentifier</key>
    <string>com.proxy-gateway.${DOMAIN}</string>
    <key>PayloadOrganization</key>
    <string>Proxy Gateway</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF

    cat > "${WWW_DIR}/index.html" <<EOF
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Proxy Gateway iOS DoT</title>
</head>
<body>
  <h1>Proxy Gateway iOS DoT</h1>
  <p><a href="/ios-dot.mobileconfig">下载 iOS 蜂窝网络 DoT 描述文件</a></p>
</body>
</html>
EOF

    cat > /etc/systemd/system/proxy-gateway-ios-profile.service <<EOF
[Unit]
Description=Proxy Gateway iOS profile static server
After=network.target

[Service]
Type=simple
WorkingDirectory=${WWW_DIR}
ExecStart=/usr/bin/python3 -m http.server ${IOS_PROFILE_PORT} --bind 0.0.0.0
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now proxy-gateway-ios-profile.service

    echo "$profile_url" > "${WWW_DIR}/ios-profile-url.txt"
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ANSIUTF8 "$profile_url" | tee "${WWW_DIR}/ios-dot.qr.txt"
    else
        warn "qrencode is not installed; QR code skipped. Profile URL: $profile_url"
    fi

    ok "iOS profile ready: $profile_url"
}

# =============================================================================
# System tuning
# =============================================================================
system_tuning() {
    info "Applying kernel and system tuning..."

    modprobe nf_conntrack >/dev/null 2>&1 || true
    mkdir -p /etc/modules-load.d
    echo nf_conntrack > /etc/modules-load.d/proxy-gateway-net.conf

    cat > /etc/sysctl.d/99-proxy-gateway.conf <<'EOF'
# Proxy Gateway Optimizations
fs.file-max=10240000
fs.nr_open=2097152
net.core.default_qdisc=fq
net.core.netdev_max_backlog=65536
net.core.somaxconn=10240000
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.ip_default_ttl=128
net.ipv4.ip_forward=1
net.ipv4.ip_local_port_range=10240 65535
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_dsack=1
net.ipv4.tcp_ecn=1
net.ipv4.tcp_fastopen=1027
net.ipv4.tcp_fastopen_blackhole_timeout_sec=0
net.ipv4.tcp_fin_timeout=2
net.ipv4.tcp_keepalive_intvl=5
net.ipv4.tcp_keepalive_probes=2
net.ipv4.tcp_keepalive_time=120
net.ipv4.tcp_max_orphans=10240
net.ipv4.tcp_max_syn_backlog=65536
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_retries1=2
net.ipv4.tcp_retries2=2
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_rmem=8192 65536 134217728
net.ipv4.tcp_moderate_rcvbuf=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_wmem=8192 131072 134217728
net.netfilter.nf_conntrack_generic_timeout=10
net.netfilter.nf_conntrack_icmp_timeout=2
net.netfilter.nf_conntrack_max=10240000
net.netfilter.nf_conntrack_tcp_max_retrans=2
net.netfilter.nf_conntrack_tcp_timeout_close=2
net.netfilter.nf_conntrack_tcp_timeout_close_wait=2
net.netfilter.nf_conntrack_tcp_timeout_established=30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait=2
net.netfilter.nf_conntrack_tcp_timeout_last_ack=2
net.netfilter.nf_conntrack_tcp_timeout_max_retrans=2
net.netfilter.nf_conntrack_tcp_timeout_syn_recv=2
net.netfilter.nf_conntrack_tcp_timeout_syn_sent=2
net.netfilter.nf_conntrack_tcp_timeout_time_wait=2
net.netfilter.nf_conntrack_tcp_timeout_unacknowledged=2
net.netfilter.nf_conntrack_udp_timeout=2
net.netfilter.nf_conntrack_udp_timeout_stream=30
vm.swappiness=0
EOF

    local mem_pages
    mem_pages=$(awk '/MemTotal/ { printf "%d", ($2 * 1024) / 4096 }' /proc/meminfo 2>/dev/null || echo "")
    if [[ -n "$mem_pages" && "$mem_pages" -gt 0 ]]; then
        {
            echo "net.ipv4.tcp_mem=$((mem_pages / 100 * 12)) $((mem_pages / 100 * 50)) $((mem_pages / 100 * 70))"
        } >> /etc/sysctl.d/99-proxy-gateway.conf
    fi

    sysctl --system >/dev/null

    # PAM limits (avoid duplicate entries)
    if ! grep -q "proxy-gateway-limits" /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf <<'EOF'
# proxy-gateway-limits
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
    fi

    mkdir -p /etc/systemd/system
    cat > /etc/systemd/system/disable-transparent-huge-pages.service <<'EOF'
[Unit]
Description=Disable Transparent Huge Pages (THP)
DefaultDependencies=no
After=sysinit.target local-fs.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'test -w /sys/kernel/mm/transparent_hugepage/enabled && echo never > /sys/kernel/mm/transparent_hugepage/enabled || true'
ExecStart=/bin/sh -c 'test -w /sys/kernel/mm/transparent_hugepage/defrag && echo never > /sys/kernel/mm/transparent_hugepage/defrag || true'

[Install]
WantedBy=basic.target
EOF

    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/99-proxy-gateway.conf <<'EOF'
[Journal]
SystemMaxUse=384M
SystemMaxFileSize=128M
ForwardToSyslog=no
EOF

    systemctl daemon-reload
    systemctl enable --now disable-transparent-huge-pages.service 2>/dev/null || true
    systemctl restart systemd-journald 2>/dev/null || true

    ok "System tuning applied"
}

# =============================================================================
# Firewall (nftables preferred, fallback to iptables)
# =============================================================================
setup_firewall() {
    info "Configuring firewall..."
    local socks_port="" socks_cidr="" wg_port=""
    local socks_nft_rule="" wg_nft_rule=""

    socks_port=$(cat "${CONF_DIR}/.socks5_port" 2>/dev/null || true)
    socks_cidr=$(cat "${CONF_DIR}/.socks5_client_cidr" 2>/dev/null || true)
    wg_port=$(cat "${CONF_DIR}/.wg_port" 2>/dev/null || true)
    if [[ "$socks_port" =~ ^[0-9]+$ && -n "$socks_cidr" ]]; then
        socks_nft_rule="        ip saddr ${socks_cidr} tcp dport ${socks_port} accept"
    fi
    if [[ "$wg_port" =~ ^[0-9]+$ ]]; then
        wg_nft_rule="        udp dport ${wg_port} accept"
    fi

    if command -v nft >/dev/null 2>&1; then
        # nftables
        cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        tcp dport { 22, 53, 853, 8111 } accept
        udp dport 53 accept
        ip saddr 172.22.0.0/16 tcp dport { 80, 443 } accept
        ip saddr 172.22.0.0/16 udp dport 443 accept
${socks_nft_rule}
${wg_nft_rule}
        # ICMP for basic network health
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
        chmod +x /etc/nftables.conf
        nft -f /etc/nftables.conf 2>/dev/null || true
        systemctl enable nftables 2>/dev/null || true
    else
        # iptables fallback
        iptables -F INPUT
        iptables -P INPUT DROP
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p tcp -m multiport --dports 22,53,853,8111 -j ACCEPT
        iptables -A INPUT -p udp --dport 53 -j ACCEPT
        iptables -A INPUT -s 172.22.0.0/16 -p tcp -m multiport --dports 80,443 -j ACCEPT
        iptables -A INPUT -s 172.22.0.0/16 -p udp --dport 443 -j ACCEPT
        if [[ "$socks_port" =~ ^[0-9]+$ && -n "$socks_cidr" ]]; then
            iptables -A INPUT -s "$socks_cidr" -p tcp --dport "$socks_port" -j ACCEPT
        fi
        if [[ "$wg_port" =~ ^[0-9]+$ ]]; then
            iptables -A INPUT -p udp --dport "$wg_port" -j ACCEPT
        fi
        iptables -A INPUT -p icmp -j ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT

        # Save rules
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables.rules 2>/dev/null || true
        fi
    fi

    ok "Firewall configured (reverse proxy whitelist: 172.22.0.0/16)"
}

setup_socks_only_firewall() {
    local socks_port="$1"
    local allow_cidr="$2"
    info "Configuring SOCKS5-only firewall..."

    if command -v nft >/dev/null 2>&1; then
        cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        tcp dport 22 accept
        ip saddr ${allow_cidr} tcp dport ${socks_port} accept
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
        chmod +x /etc/nftables.conf
        nft -f /etc/nftables.conf 2>/dev/null || true
        systemctl enable nftables 2>/dev/null || true
    else
        iptables -F INPUT
        iptables -P INPUT DROP
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -s "$allow_cidr" -p tcp --dport "$socks_port" -j ACCEPT
        iptables -A INPUT -p icmp -j ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        command -v iptables-save >/dev/null 2>&1 && iptables-save > /etc/iptables.rules 2>/dev/null || true
    fi
    ok "SOCKS5-only firewall configured"
}

open_cert_http_port() {
    info "Temporarily opening TCP/80 for Let's Encrypt HTTP-01..."

    if command -v nft >/dev/null 2>&1 && nft list table inet filter >/dev/null 2>&1; then
        nft insert rule inet filter input tcp dport 80 accept 2>/dev/null || true
    elif command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT 1 -p tcp --dport 80 -m comment --comment proxy-gateway-cert-http -j ACCEPT 2>/dev/null || true
    fi
}

restore_reverse_proxy_firewall() {
    info "Restoring reverse proxy firewall whitelist..."
    setup_firewall >/dev/null 2>&1 || true
}

install_certbot_firewall_hooks() {
    mkdir -p /etc/letsencrypt/renewal-hooks/pre /etc/letsencrypt/renewal-hooks/post

    cat > /usr/local/bin/proxy-gateway-open-cert-http.sh <<'EOF'
#!/bin/bash
set -e
if command -v nft >/dev/null 2>&1 && nft list table inet filter >/dev/null 2>&1; then
    nft insert rule inet filter input tcp dport 80 accept 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT 1 -p tcp --dport 80 -m comment --comment proxy-gateway-cert-http -j ACCEPT 2>/dev/null || true
fi
EOF
    cat > /usr/local/bin/proxy-gateway-restore-firewall.sh <<'EOF'
#!/bin/bash
set -e
if command -v nft >/dev/null 2>&1 && [[ -f /etc/nftables.conf ]]; then
    nft -f /etc/nftables.conf 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
    while iptables -D INPUT -p tcp --dport 80 -m comment --comment proxy-gateway-cert-http -j ACCEPT 2>/dev/null; do :; done
fi
EOF
    chmod +x /usr/local/bin/proxy-gateway-open-cert-http.sh /usr/local/bin/proxy-gateway-restore-firewall.sh
    cp /usr/local/bin/proxy-gateway-open-cert-http.sh /etc/letsencrypt/renewal-hooks/pre/10-proxy-gateway-open-http.sh
    cp /usr/local/bin/proxy-gateway-restore-firewall.sh /etc/letsencrypt/renewal-hooks/post/90-proxy-gateway-restore-firewall.sh
    chmod +x /etc/letsencrypt/renewal-hooks/pre/10-proxy-gateway-open-http.sh \
        /etc/letsencrypt/renewal-hooks/post/90-proxy-gateway-restore-firewall.sh
}

# =============================================================================
# Optional RethinkDNS WireGuard fallback
# =============================================================================
install_wireguard_fallback() {
    check_root
    detect_os
    get_public_ip 2>/dev/null || true
    local wg_port server_addr client_addr wan_if answer
    local server_private server_public client_private client_public

    tty_read wg_port "WireGuard listen UDP port" "$DEFAULT_WG_PORT"
    [[ "$wg_port" =~ ^[0-9]+$ ]] || { err "Invalid WireGuard port: $wg_port"; return 1; }
    tty_read server_addr "WireGuard server tunnel address" "$DEFAULT_WG_SERVER_ADDR"
    tty_read client_addr "RethinkDNS client tunnel address" "$DEFAULT_WG_CLIENT_ADDR"

    if ! command -v wg >/dev/null 2>&1 || ! command -v wg-quick >/dev/null 2>&1; then
        info "Installing wireguard-tools..."
        if [[ "$PKG_MANAGER" == "apt" ]]; then
            apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools iptables
        else
            $PKG_MANAGER install -y wireguard-tools iptables
        fi
    fi

    mkdir -p /etc/wireguard "$CONF_DIR" "${BASE_DIR}/wireguard"
    chmod 700 /etc/wireguard

    server_private=$(wg genkey)
    server_public=$(printf '%s' "$server_private" | wg pubkey)
    client_private=$(wg genkey)
    client_public=$(printf '%s' "$client_private" | wg pubkey)
    wan_if=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
    wan_if="${wan_if:-eth0}"

    cat > /etc/wireguard/pgw-rdns.conf <<EOF
[Interface]
Address = ${server_addr}
ListenPort = ${wg_port}
PrivateKey = ${server_private}
PostUp = iptables -t nat -A POSTROUTING -s ${client_addr%/*} -o ${wan_if} -j MASQUERADE; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s ${client_addr%/*} -o ${wan_if} -j MASQUERADE; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT

[Peer]
PublicKey = ${client_public}
AllowedIPs = ${client_addr}
EOF
    chmod 600 /etc/wireguard/pgw-rdns.conf

    cat > "${BASE_DIR}/wireguard/rethinkdns-client.conf" <<EOF
[Interface]
PrivateKey = ${client_private}
Address = ${client_addr}
DNS = ${PUBLIC_IP:-}

[Peer]
PublicKey = ${server_public}
Endpoint = ${PUBLIC_IP:-<VPS1-IP>}:${wg_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    chmod 600 "${BASE_DIR}/wireguard/rethinkdns-client.conf"

    echo "$wg_port" > "${CONF_DIR}/.wg_port"
    setup_firewall
    systemctl enable --now wg-quick@pgw-rdns

    ok "WireGuard fallback installed"
    echo "Client config: ${BASE_DIR}/wireguard/rethinkdns-client.conf"
    tty_yes_no answer "Show client config now?" "Y"
    if [[ "$answer" == "y" ]]; then
        cat "${BASE_DIR}/wireguard/rethinkdns-client.conf"
        pause_return
    fi
}

# =============================================================================
# Optional RethinkDNS SOCKS5 fallback (sing-box)
# =============================================================================
find_singbox_candidate() {
    SINGBOX_BIN=""
    SINGBOX_CONFIG=""
    SINGBOX_SERVICE=""

    local home_dir candidate_bin candidate_config unit process_line
    for home_dir in "${HOME:-}" /root; do
        [[ -z "$home_dir" ]] && continue
        candidate_bin="${home_dir}/agsbx/sing-box"
        candidate_config="${home_dir}/agsbx/sb.json"
        if [[ -x "$candidate_bin" && -f "$candidate_config" ]]; then
            SINGBOX_BIN="$candidate_bin"
            SINGBOX_CONFIG="$candidate_config"
            SINGBOX_SERVICE=""
            return 0
        fi
    done

    process_line=$(pgrep -af 'sing-box.*run.*-c|agsbx/.*/s|agsbx/sing-box' 2>/dev/null | head -n1 || true)
    if [[ -n "$process_line" ]]; then
        SINGBOX_BIN=$(awk '{for (i=2;i<=NF;i++) if ($i ~ /sing-box$/ || $i ~ /agsbx\/s$/) {print $i; exit}}' <<< "$process_line")
        SINGBOX_CONFIG=$(sed -n 's/.*-c[ =]\([^ ]*\.json\).*/\1/p' <<< "$process_line" | head -n1)
        [[ -n "$SINGBOX_BIN" && -n "$SINGBOX_CONFIG" ]] && return 0
    fi

    if command -v sing-box >/dev/null 2>&1; then
        SINGBOX_BIN=$(command -v sing-box)
        for candidate_config in /etc/sing-box/config.json /usr/local/etc/sing-box/config.json; do
            if [[ -f "$candidate_config" ]]; then
                SINGBOX_CONFIG="$candidate_config"
                break
            fi
        done
        unit=$(systemctl list-units --type=service --all 'sing*box*.service' --no-legend 2>/dev/null | awk '{print $1; exit}' || true)
        SINGBOX_SERVICE="$unit"
        [[ -n "$SINGBOX_CONFIG" ]] && return 0
    fi

    return 1
}

install_singbox_if_missing() {
    local installer
    if command -v sing-box >/dev/null 2>&1; then
        SINGBOX_BIN=$(command -v sing-box)
        return 0
    fi
    info "Installing sing-box from official install script..."
    installer=$(mktemp)
    curl -fsSL https://sing-box.app/install.sh -o "$installer"
    sh "$installer"
    rm -f "$installer"
    SINGBOX_BIN=$(command -v sing-box || true)
    [[ -n "$SINGBOX_BIN" ]] || { err "sing-box installation failed"; return 1; }
}

write_singbox_socks_config() {
    local output_path="$1"
    local listen_addr="$2"
    local listen_port="$3"
    local username="$4"
    local password="$5"
    local upstream_host="$6"
    local upstream_port="$7"
    local upstream_user="$8"
    local upstream_pass="$9"

    python3 - "$output_path" "$listen_addr" "$listen_port" "$username" "$password" "$upstream_host" "$upstream_port" "$upstream_user" "$upstream_pass" <<'PYEOF'
import json
import os
import sys

path, listen_addr, listen_port, username, password, upstream_host, upstream_port, upstream_user, upstream_pass = sys.argv[1:10]
data = {}
if os.path.exists(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

data.setdefault("log", {"level": "info"})
inbounds = [x for x in data.get("inbounds", []) if x.get("tag") != "proxy-gateway-socks-in"]
outbounds = [x for x in data.get("outbounds", []) if x.get("tag") != "proxy-gateway-socks-out"]

inbounds.append({
    "type": "socks",
    "tag": "proxy-gateway-socks-in",
    "listen": listen_addr,
    "listen_port": int(listen_port),
    "users": [{"username": username, "password": password}],
})
if upstream_host:
    outbounds.append({
        "type": "socks",
        "tag": "proxy-gateway-socks-out",
        "server": upstream_host,
        "server_port": int(upstream_port or 1080),
        "version": "5",
        "username": upstream_user,
        "password": upstream_pass,
    })
else:
    outbounds.append({"type": "direct", "tag": "proxy-gateway-socks-out"})

route = data.setdefault("route", {})
rules = [x for x in route.get("rules", []) if x.get("outbound") != "proxy-gateway-socks-out"]
rules.insert(0, {"inbound": ["proxy-gateway-socks-in"], "outbound": "proxy-gateway-socks-out"})
route["rules"] = rules
data["inbounds"] = inbounds
data["outbounds"] = outbounds

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
    f.write("\n")
PYEOF
}

restart_singbox_candidate() {
    local service="$1"
    local bin="$2"
    local config="$3"
    if [[ -n "$service" ]]; then
        systemctl restart "$service"
    else
        warn "No systemd service detected for existing sing-box. Restart it manually if argosbx does not reload automatically:"
        warn "  ${bin} run -c ${config}"
    fi
}

install_socks5_fallback() {
    check_root
    get_public_ip 2>/dev/null || true
    local listen_addr="0.0.0.0" listen_port username password client_cidr
    local upstream_enabled upstream_host upstream_port upstream_user upstream_pass
    local action="" tmp_config backup_config answer

    tty_read listen_addr "SOCKS5 listen address" "0.0.0.0"
    tty_read listen_port "SOCKS5 listen port" "$DEFAULT_SOCKS5_PORT"
    [[ "$listen_port" =~ ^[0-9]+$ ]] || { err "Invalid SOCKS5 port: $listen_port"; return 1; }
    tty_read username "SOCKS5 username" "$DEFAULT_SOCKS5_USER"
    password=$(random_secret)
    tty_read password "SOCKS5 password" "$password"
    tty_read client_cidr "Allowed client CIDR" "$DEFAULT_CLIENT_CIDR"
    tty_yes_no upstream_enabled "Chain this SOCKS5 inbound to a VPS2 SOCKS5 upstream?" "N"
    if [[ "$upstream_enabled" == "y" ]]; then
        tty_read upstream_host "VPS2 SOCKS5 host" ""
        tty_read upstream_port "VPS2 SOCKS5 port" "$DEFAULT_SOCKS5_PORT"
        tty_read upstream_user "VPS2 SOCKS5 username" "$DEFAULT_SOCKS5_USER"
        tty_read upstream_pass "VPS2 SOCKS5 password" ""
    else
        upstream_host=""
        upstream_port=""
        upstream_user=""
        upstream_pass=""
    fi

    mkdir -p "$CONF_DIR"
    echo "$listen_port" > "${CONF_DIR}/.socks5_port"
    echo "$client_cidr" > "${CONF_DIR}/.socks5_client_cidr"

    if find_singbox_candidate; then
        echo ""
        echo "Detected existing sing-box:"
        echo "  Binary: ${SINGBOX_BIN}"
        echo "  Config: ${SINGBOX_CONFIG}"
        echo "  Service: ${SINGBOX_SERVICE:-none detected}"
        echo ""
        echo "请选择 SOCKS5 安装方式："
        echo "  1) 复用现有 sing-box，备份并追加 inbound（推荐）"
        echo "  2) 新建独立 proxy-gateway-socks.service"
        echo "  3) 跳过 SOCKS5"
        while true; do
            tty_read action "请输入序号 (1-3)" "1"
            case "$action" in
                1|2|3) break ;;
                *) warn "无效输入，请重新输入 1-3 之间的数字" ;;
            esac
        done
    else
        action="2"
    fi

    case "$action" in
        1)
            tmp_config=$(mktemp)
            backup_config="${SINGBOX_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
            cp "$SINGBOX_CONFIG" "$tmp_config"
            write_singbox_socks_config "$tmp_config" "$listen_addr" "$listen_port" "$username" "$password" "$upstream_host" "$upstream_port" "$upstream_user" "$upstream_pass"
            if "$SINGBOX_BIN" check -c "$tmp_config"; then
                cp "$SINGBOX_CONFIG" "$backup_config"
                cp "$tmp_config" "$SINGBOX_CONFIG"
                restart_singbox_candidate "$SINGBOX_SERVICE" "$SINGBOX_BIN" "$SINGBOX_CONFIG"
                ok "SOCKS5 inbound added to existing sing-box"
                echo "Backup: $backup_config"
            else
                rm -f "$tmp_config"
                err "sing-box config check failed; existing config unchanged"
                return 1
            fi
            rm -f "$tmp_config"
            ;;
        2)
            install_singbox_if_missing
            mkdir -p /etc/sing-box /etc/systemd/system
            write_singbox_socks_config /etc/sing-box/proxy-gateway-socks.json "$listen_addr" "$listen_port" "$username" "$password" "$upstream_host" "$upstream_port" "$upstream_user" "$upstream_pass"
            "$SINGBOX_BIN" check -c /etc/sing-box/proxy-gateway-socks.json
            cat > /etc/systemd/system/proxy-gateway-socks.service <<EOF
[Unit]
Description=Proxy Gateway SOCKS5 fallback
After=network.target

[Service]
Type=simple
ExecStart=${SINGBOX_BIN} run -c /etc/sing-box/proxy-gateway-socks.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable --now proxy-gateway-socks
            ok "Independent SOCKS5 service installed"
            ;;
        3)
            warn "SOCKS5 setup skipped"
            return 0
            ;;
    esac

    setup_firewall
    echo ""
    echo "SOCKS5 for RethinkDNS:"
    echo "  Host: ${PUBLIC_IP:-<VPS1-IP>}"
    echo "  Port: ${listen_port}"
    echo "  Username: ${username}"
    echo "  Password: ${password}"
    echo "  Allowed source: ${client_cidr}"
    pause_return
}

install_vps2_socks_exit() {
    check_root
    get_public_ip 2>/dev/null || true
    local listen_addr="0.0.0.0" listen_port username password allow_cidr

    tty_read listen_addr "VPS2 SOCKS5 listen address" "0.0.0.0"
    tty_read listen_port "VPS2 SOCKS5 listen port" "$DEFAULT_SOCKS5_PORT"
    tty_read username "VPS2 SOCKS5 username" "$DEFAULT_SOCKS5_USER"
    password=$(random_secret)
    tty_read password "VPS2 SOCKS5 password" "$password"
    tty_read allow_cidr "Allowed VPS1 IP/CIDR" ""
    [[ -z "$allow_cidr" ]] && { err "Allowed VPS1 IP/CIDR is required"; return 1; }

    mkdir -p "$CONF_DIR"
    echo "$listen_port" > "${CONF_DIR}/.socks5_port"
    echo "$allow_cidr" > "${CONF_DIR}/.socks5_client_cidr"
    install_singbox_if_missing
    mkdir -p /etc/sing-box
    write_singbox_socks_config /etc/sing-box/proxy-gateway-upstream-socks.json "$listen_addr" "$listen_port" "$username" "$password" "" "" "" ""
    "$SINGBOX_BIN" check -c /etc/sing-box/proxy-gateway-upstream-socks.json
    cat > /etc/systemd/system/proxy-gateway-upstream-socks.service <<EOF
[Unit]
Description=Proxy Gateway upstream SOCKS5 exit
After=network.target

[Service]
Type=simple
ExecStart=${SINGBOX_BIN} run -c /etc/sing-box/proxy-gateway-upstream-socks.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now proxy-gateway-upstream-socks
    setup_socks_only_firewall "$listen_port" "$allow_cidr"

    ok "VPS2 SOCKS5 exit installed"
    echo "VPS2 SOCKS5 address: ${PUBLIC_IP:-<VPS2-IP>}"
    echo "VPS2 SOCKS5 port: ${listen_port}"
    echo "VPS2 SOCKS5 username: ${username}"
    echo "VPS2 SOCKS5 password: ${password}"
    pause_return
}

# =============================================================================
# Start services
# =============================================================================
start_services() {
    info "Starting services..."
    systemctl restart china-dns-race-proxy || { err "china-dns-race-proxy failed to start"; journalctl -u china-dns-race-proxy --no-pager -n 20; exit 1; }
    systemctl restart dnsdist || { err "dnsdist failed to start"; journalctl -u dnsdist --no-pager -n 20; exit 1; }
    systemctl restart sniproxy || { err "sniproxy failed to start"; journalctl -u sniproxy --no-pager -n 20; exit 1; }
    systemctl restart quic-proxy || { err "quic-proxy failed to start"; journalctl -u quic-proxy --no-pager -n 20; exit 1; }
    ok "All services started"
}

# =============================================================================
# Cron / Systemd timers
# =============================================================================
setup_schedules() {
    info "Setting up automatic updates..."

    # Weekly rule update (Sunday 03:00)
    cat > /etc/systemd/system/update-dnsdist-rules.timer <<'EOF'
[Unit]
Description=Weekly dnsdist rules update

[Timer]
OnCalendar=Sun *-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    cat > /etc/systemd/system/update-dnsdist-rules.service <<'EOF'
[Unit]
Description=Update dnsdist GFWList/ChinaList rules

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-dnsdist-rules.sh
EOF

    systemctl daemon-reload
    systemctl enable --now update-dnsdist-rules.timer

    install_certbot_firewall_hooks

    # Ensure certbot timer is enabled
    systemctl enable --now certbot.timer 2>/dev/null || true

    ok "Schedules configured (rules: weekly, cert: auto)"
}

# =============================================================================
# Status / Uninstall / Helpers
# =============================================================================
show_status() {
    echo "=========================================="
    echo "      Proxy Gateway Status"
    echo "=========================================="
    for svc in dnsdist sniproxy quic-proxy china-dns-race-proxy proxy-gateway-ios-profile proxy-gateway-socks proxy-gateway-upstream-socks wg-quick@pgw-rdns; do
        status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        if [[ "$status" == "active" ]]; then
            echo -e "$svc: ${GREEN}running${NC}"
        else
            echo -e "$svc: ${RED}$status${NC}"
        fi
    done
    echo ""
    if [[ -f "${CONF_DIR}/.domain" ]]; then
        echo "Domain: $(cat "${CONF_DIR}/.domain")"
    fi
    if [[ -f "${CONF_DIR}/.other_policy" ]]; then
        echo "Other policy: $(cat "${CONF_DIR}/.other_policy")"
    fi
    if [[ -f "${CONF_DIR}/.cache_size" ]]; then
        echo "DNS cache size: $(cat "${CONF_DIR}/.cache_size")"
    fi
    if [[ -f "${CONF_DIR}/.socks5_port" ]]; then
        echo "SOCKS5 port: $(cat "${CONF_DIR}/.socks5_port")"
    fi
    if [[ -f "${CONF_DIR}/.wg_port" ]]; then
        echo "WireGuard port: $(cat "${CONF_DIR}/.wg_port")"
    fi
    echo "Public IP: ${PUBLIC_IP:-N/A}"
    echo "=========================================="
}

do_uninstall() {
    warn "This will remove proxy-gateway services, dnsdist configs, optional SOCKS5/WireGuard units, and rules."
    tty_read confirm "Are you sure? [y/N]" ""
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "Uninstall cancelled"; exit 0; }

    systemctl stop dnsdist sniproxy quic-proxy china-dns-race-proxy proxy-gateway-ios-profile proxy-gateway-socks proxy-gateway-upstream-socks wg-quick@pgw-rdns 2>/dev/null || true
    systemctl disable dnsdist sniproxy quic-proxy china-dns-race-proxy proxy-gateway-ios-profile proxy-gateway-socks proxy-gateway-upstream-socks wg-quick@pgw-rdns 2>/dev/null || true
    rm -f /etc/systemd/system/{sniproxy,quic-proxy,china-dns-race-proxy,proxy-gateway-ios-profile,update-dnsdist-rules,proxy-gateway-socks,proxy-gateway-upstream-socks}.*
    systemctl daemon-reload

    rm -rf "$BASE_DIR" /etc/sniproxy.conf /etc/dnsdist /usr/local/bin/update-dnsdist-rules.sh /etc/sing-box/proxy-gateway-socks.json /etc/sing-box/proxy-gateway-upstream-socks.json
    rm -f /etc/wireguard/pgw-rdns.conf
    rm -f /usr/local/sbin/sniproxy
    rm -f /etc/letsencrypt/renewal-hooks/deploy/99-reload-dnsdist.sh
    rm -f /etc/sysctl.d/99-proxy-gateway.conf
    rm -f /etc/profile.d/go.sh

    # Optionally remove certbot certs
    warn "SSL certificates in /etc/letsencrypt/live/ are kept. Remove manually if needed."

    ok "Uninstall completed"
}

force_renew_cert() {
    if [[ -f "${CONF_DIR}/.domain" ]]; then
        DOMAIN=$(cat "${CONF_DIR}/.domain")
    fi
    if [[ -z "${DOMAIN:-}" ]]; then
        err "No domain found. Cannot renew."
        exit 1
    fi

    local certbot_cmd
    certbot_cmd=(certbot certonly --standalone -d "$DOMAIN" --force-renewal \
        --agree-tos -n -m "${EMAIL:-admin@${DOMAIN}}" \
        --pre-hook /usr/local/bin/proxy-gateway-open-cert-http.sh \
        --post-hook /usr/local/bin/proxy-gateway-restore-firewall.sh)

    open_cert_http_port
    trap restore_reverse_proxy_firewall RETURN

    if ! "${certbot_cmd[@]}"; then
        # Check for known Python compatibility error
        if certbot --version 2>&1 | grep -q "AttributeError" || \
           "${certbot_cmd[@]}" 2>&1 | grep -q "AttributeError"; then
            warn "Certbot compatibility error detected. Attempting to fix Python dependencies..."
            pip3 install --upgrade --break-system-packages certbot josepy cryptography 2>/dev/null || \
                pip3 install --upgrade certbot josepy cryptography 2>/dev/null || true
            info "Retrying certificate renewal..."
            "${certbot_cmd[@]}" || { err "Certificate renewal failed"; exit 1; }
        else
            err "Certificate renewal failed"
            exit 1
        fi
    fi

    # Re-copy certificates to dnsdist-readable location
    local cert_live_dir="/etc/letsencrypt/live/${DOMAIN}"
    if [[ -d "$cert_live_dir" ]]; then
        mkdir -p /etc/dnsdist/certs
        cp "${cert_live_dir}/fullchain.pem" /etc/dnsdist/certs/fullchain.pem
        cp "${cert_live_dir}/privkey.pem" /etc/dnsdist/certs/privkey.pem
        chown -R _dnsdist:_dnsdist /etc/dnsdist/certs/
        chmod 640 /etc/dnsdist/certs/*.pem
    fi

    if systemctl is-active --quiet dnsdist; then
        systemctl reload dnsdist && ok "Certificate renewed and dnsdist reloaded"
    else
        systemctl start dnsdist && ok "Certificate renewed and dnsdist started"
    fi
}

regenerate_ios_profile() {
    if [[ -f "${CONF_DIR}/.domain" ]]; then
        DOMAIN=$(cat "${CONF_DIR}/.domain")
    elif [[ -f /etc/dnsdist/.domain ]]; then
        DOMAIN=$(cat /etc/dnsdist/.domain)
    fi

    if [[ -f /etc/dnsdist/.public_ip ]]; then
        PUBLIC_IP=$(cat /etc/dnsdist/.public_ip)
    else
        get_public_ip
    fi

    if [[ -z "${DOMAIN:-}" ]]; then
        err "No domain found. Cannot generate iOS profile."
        exit 1
    fi

    generate_ios_profile
}

# =============================================================================
# Main installation flow
# =============================================================================
main_install() {
    check_root
    detect_os
    get_public_ip
    check_port_53

    echo ""
    echo "=========================================="
    echo "  高性能反代系统一键部署"
    echo "=========================================="
    echo ""

    install_deps
    generate_domain
    register_domain_cloudns
    install_cert
    configure_overseas_dns
    configure_dns_policy
    install_sniproxy
    install_quic_proxy
    install_china_dns_race_proxy
    install_dnsdist
    init_rules
    system_tuning
    setup_firewall
    generate_ios_profile
    start_services
    setup_schedules

    echo ""
    echo "=========================================="
    echo "         部署完成！"
    echo "=========================================="
    echo ""
    echo "DoT 地址:  tls://${DOMAIN}:853"
    echo "TCP 代理:  ${PUBLIC_IP}:80, ${PUBLIC_IP}:443 (sniproxy)"
    echo "UDP 代理:  ${PUBLIC_IP}:443 (quic-proxy)"
    echo "DNS 查询:  ${PUBLIC_IP}:53"
    echo "iOS 描述文件: http://${DOMAIN}:${IOS_PROFILE_PORT}/ios-dot.mobileconfig"
    echo ""
    echo "客户端配置示例 (Android 私人 DNS):"
    echo "  ${DOMAIN}"
    echo "iOS 扫码安装:"
    if [[ -f "${WWW_DIR}/ios-dot.qr.txt" ]]; then
        cat "${WWW_DIR}/ios-dot.qr.txt"
    fi
    echo ""
    echo "管理命令:"
    echo "  $0 --status"
    echo "  $0 --update-rules"
    echo "  $0 --renew-cert"
    echo "  $0 -ios"
    echo "  $0 --uninstall"
    echo "=========================================="
}

main_menu() {
    local choice=""

    while true; do
        echo ""
        echo "=========================================="
        echo "  Proxy Gateway Plus"
        echo "=========================================="
        echo "  1) 安装核心 DNS + SNI/QUIC 网关"
        echo "  2) 配置 DNS 分流策略"
        echo "  3) 管理自定义分流列表"
        echo "  4) 添加 RethinkDNS WireGuard 兜底入口"
        echo "  5) 添加 RethinkDNS SOCKS5 兜底入口"
        echo "  6) 安装可选 VPS2 SOCKS5 出口"
        echo "  7) 立即更新 DNS 规则"
        echo "  8) 查看状态"
        echo "  9) 续期证书"
        echo " 10) 重新生成 iOS 描述文件"
        echo " 11) 卸载"
        echo "  0) 退出"
        echo "=========================================="
        tty_read choice "请输入序号 (0-11)" ""
        case "$choice" in
            1)
                main_install
                pause_return
                ;;
            2)
                configure_dns_policy
                pause_return
                ;;
            3)
                configure_custom_lists_menu
                ;;
            4)
                install_wireguard_fallback
                pause_return
                ;;
            5)
                install_socks5_fallback
                ;;
            6)
                install_vps2_socks_exit
                ;;
            7)
                if [[ -x /usr/local/bin/update-dnsdist-rules.sh ]]; then
                    /usr/local/bin/update-dnsdist-rules.sh
                else
                    warn "update-dnsdist-rules.sh not installed yet; run core installation first."
                fi
                pause_return
                ;;
            8)
                get_public_ip 2>/dev/null || true
                show_status
                pause_return
                ;;
            9)
                force_renew_cert
                pause_return
                ;;
            10)
                regenerate_ios_profile
                pause_return
                ;;
            11)
                do_uninstall
                pause_return
                ;;
            0)
                echo "Bye."
                return 0
                ;;
            *)
                warn "无效输入，请重新输入 0-11 之间的数字"
                ;;
        esac
    done
}

# =============================================================================
# Entrypoint
# =============================================================================
case "${1:-}" in
    --status)
        get_public_ip 2>/dev/null || true
        show_status
        ;;
    --update-rules)
        /usr/local/bin/update-dnsdist-rules.sh
        ;;
    --renew-cert)
        force_renew_cert
        ;;
    --uninstall)
        do_uninstall
        ;;
    -ios)
        regenerate_ios_profile
        ;;
    -h|--help|help)
        usage
        ;;
    "")
        bootstrap_full_repo_if_needed "$@"
        main_menu
        ;;
    *)
        err "Unknown option: $1"
        usage
        exit 1
        ;;
esac
