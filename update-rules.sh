#!/bin/bash
set -euo pipefail

BASE_DIR="/etc/dnsdist"
GFWLIST_URL="https://github.com/gfwlist/gfwlist/raw/master/gfwlist.txt"
CHINALIST_URL="https://github.com/felixonmars/dnsmasq-china-list/raw/master/accelerated-domains.china.conf"
GFWLIST_FILE="${BASE_DIR}/gfwlist.raw"
CHINALIST_FILE="${BASE_DIR}/chinalist.raw"
GFWLIST_LUA="${BASE_DIR}/gfwlist.lua"
CHINALIST_LUA="${BASE_DIR}/chinalist.lua"
PROXY_EXTRA_LUA="${BASE_DIR}/proxy-extra.lua"
DIRECT_EXTRA_LUA="${BASE_DIR}/direct-extra.lua"
CHINALIST_CHUNK_DIR="${BASE_DIR}/chinalist.d"
CHINALIST_CHUNK_SIZE=20000
GFWLIST_EXTRA_FILE="${BASE_DIR}/gfwlist-extra-local.txt"
PROXY_EXTRA_FILE="${BASE_DIR}/proxy-extra-local.txt"
DIRECT_EXTRA_FILE="${BASE_DIR}/direct-extra-local.txt"
CUSTOM_PROXY_LISTS_FILE="${BASE_DIR}/custom-proxy-lists.txt"
CUSTOM_DIRECT_LISTS_FILE="${BASE_DIR}/custom-direct-lists.txt"
DNSDIST_TEMPLATE="${BASE_DIR}/dnsdist.conf.template"
DNSDIST_CONF="/etc/dnsdist/dnsdist.conf"
DEFAULT_OVERSEAS_DNS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
DEFAULT_PUBLIC_OVERSEAS_DNS=("1.1.1.1" "8.8.8.8")
DEFAULT_DNS_CACHE_SIZE=200000

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
            echo "[!] Skipping invalid overseas DNS address: $item" >&2
            continue
        fi
        name="${prefix}${order}"
        printf 'newServer({address="%s:53", pool="%s", name="%s", order=%d, useClientSubnet=true})\n' "$item" "$pool" "$name" "$order"
        order=$((order + 1))
    done
}

normalize_domain() {
    local domain="$1"
    domain="${domain%%#*}"
    domain="${domain%%$'\r'}"
    domain="${domain#"${domain%%[![:space:]]*}"}"
    domain="${domain%"${domain##*[![:space:]]}"}"
    domain="${domain%.}"
    domain="${domain#www.}"
    domain="$(printf '%s' "$domain" | tr 'A-Z' 'a-z')"
    [[ -z "$domain" ]] && return 1
    [[ "$domain" =~ ^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$ ]] || return 1
    printf '%s\n' "$domain"
}

extract_domains_from_file() {
    local input_file="$1"
    local raw domain

    while IFS= read -r raw || [[ -n "$raw" ]]; do
        [[ "$raw" =~ ^[[:space:]]*[!\[] ]] && continue
        [[ "$raw" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${raw//[[:space:]]/}" ]] && continue

        domain=""
        if [[ "$raw" =~ server=/([^/]+)/ ]]; then
            domain="${BASH_REMATCH[1]}"
        elif [[ "$raw" =~ ^\|\|([^/^]+)\^? ]]; then
            domain="${BASH_REMATCH[1]}"
        elif [[ "$raw" =~ ^\|https?://([^/]+) ]]; then
            domain="${BASH_REMATCH[1]}"
        elif [[ "$raw" =~ ^\*\.(.+) ]]; then
            domain="${BASH_REMATCH[1]}"
        elif [[ "$raw" =~ ^address=/([^/]+)/ ]]; then
            domain="${BASH_REMATCH[1]}"
        elif [[ "$raw" =~ ^[[:space:]]*([A-Za-z0-9][A-Za-z0-9_.-]*\.[A-Za-z0-9_.-]+)[[:space:]]*$ ]]; then
            domain="${BASH_REMATCH[1]}"
        fi

        if [[ -n "$domain" ]]; then
            normalize_domain "$domain" || true
        fi
    done < "$input_file"
}

append_local_gfwlist_extras() {
    [[ -f "${GFWLIST_EXTRA_FILE}" ]] || return 0

    echo "[*] Loading local GFWList extras..."
    touch "${GFWLIST_LUA}"
    local gfw_domain_index="${BASE_DIR}/gfwlist.domains"
    local domain extra_count=0

    sed -n 's/^gfwList:add(newDNSName("\(.*\)"))$/\1/p' "${GFWLIST_LUA}" | sort -u > "${gfw_domain_index}"

    while IFS= read -r domain || [[ -n "${domain}" ]]; do
        domain="$(normalize_domain "$domain" || true)"
        [[ -z "${domain}" ]] && continue
        if grep -Fxq "${domain}" "${gfw_domain_index}"; then
            continue
        fi
        echo "gfwList:add(newDNSName(\"${domain}\"))" >> "${GFWLIST_LUA}"
        echo "${domain}" >> "${gfw_domain_index}"
        extra_count=$((extra_count + 1))
    done < "${GFWLIST_EXTRA_FILE}"

    rm -f "${gfw_domain_index}"
    echo "[+] Local GFWList extras: ${extra_count} domains"
}

write_extra_list_lua() {
    local local_file="$1"
    local remote_list_file="$2"
    local lua_file="$3"
    local lua_var="$4"
    local label="$5"
    local tmp_domains tmp_remote tmp_sorted url count

    tmp_domains=$(mktemp "${BASE_DIR}/${label}.domains.XXXXXX")
    tmp_remote=$(mktemp "${BASE_DIR}/${label}.remote.XXXXXX")
    tmp_sorted=$(mktemp "${BASE_DIR}/${label}.sorted.XXXXXX")
    : > "$tmp_domains"

    if [[ -f "$local_file" ]]; then
        extract_domains_from_file "$local_file" >> "$tmp_domains"
    fi

    if [[ -f "$remote_list_file" ]]; then
        while IFS= read -r url || [[ -n "$url" ]]; do
            url="${url%%#*}"
            url="${url#"${url%%[![:space:]]*}"}"
            url="${url%"${url##*[![:space:]]}"}"
            [[ -z "$url" ]] && continue
            if wget -qO "$tmp_remote" "$url" 2>/dev/null; then
                extract_domains_from_file "$tmp_remote" >> "$tmp_domains"
            else
                echo "[!] Failed to download ${label} list: ${url}" >&2
            fi
        done < "$remote_list_file"
    fi

    sort -u "$tmp_domains" > "$tmp_sorted"
    : > "$lua_file"
    count=0
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        [[ -z "$domain" ]] && continue
        echo "${lua_var}:add(newDNSName(\"${domain}\"))" >> "$lua_file"
        count=$((count + 1))
    done < "$tmp_sorted"

    rm -f "$tmp_domains" "$tmp_remote" "$tmp_sorted"
    echo "[+] ${label}: ${count} domains"
}

install_chinalist_chunks() {
    local tmp_chunk_dir="$1"
    local tmp_loader="$2"
    local old_chunk_dir="${CHINALIST_CHUNK_DIR}.old"

    rm -rf "${old_chunk_dir}"
    if [[ -d "${CHINALIST_CHUNK_DIR}" ]]; then
        mv "${CHINALIST_CHUNK_DIR}" "${old_chunk_dir}"
    fi
    mv "${tmp_chunk_dir}" "${CHINALIST_CHUNK_DIR}"
    mv "${tmp_loader}" "${CHINALIST_LUA}"
    rm -rf "${old_chunk_dir}"
}

write_chinalist_chunks() {
    local tmp_chunk_dir="$1"
    local tmp_loader="$2"
    local count=0 chunk_index=0 entries_in_chunk=0 chunk_file=""
    local chunk_paths=()
    local domain basename final_path

    mkdir -p "${tmp_chunk_dir}"

    start_chinalist_chunk() {
        printf -v basename 'chinalist-%03d.lua' "${chunk_index}"
        chunk_file="${tmp_chunk_dir}/${basename}"
        final_path="${CHINALIST_CHUNK_DIR}/${basename}"
        printf 'local chinaList = ...\n' > "${chunk_file}"
        chunk_paths+=("${final_path}")
        chunk_index=$((chunk_index + 1))
        entries_in_chunk=0
    }

    while IFS= read -r domain; do
        domain="$(normalize_domain "$domain" || true)"
        [[ -z "${domain}" ]] && continue
        if [[ ${entries_in_chunk} -eq 0 ]]; then
            start_chinalist_chunk
        fi
        echo "chinaList:add(newDNSName(\"${domain}\"))" >> "${chunk_file}"
        count=$((count + 1))
        entries_in_chunk=$((entries_in_chunk + 1))
        if [[ ${entries_in_chunk} -ge ${CHINALIST_CHUNK_SIZE} ]]; then
            entries_in_chunk=0
        fi
    done < <(grep -oP 'server=/\K[^/]+' "${CHINALIST_FILE}")

    if [[ ${#chunk_paths[@]} -eq 0 ]]; then
        echo "-- (no chinalist rules loaded)" > "${tmp_loader}"
    else
        {
            echo "local chinalistChunks = {"
            for final_path in "${chunk_paths[@]}"; do
                printf '    "%s",\n' "${final_path}"
            done
            echo "}"
            echo "for _, chunk in ipairs(chinalistChunks) do"
            echo "    assert(loadfile(chunk))(chinaList)"
            echo "end"
        } > "${tmp_loader}"
    fi

    chmod -R u=rwX,go=rX "${tmp_chunk_dir}"
    chmod 0644 "${tmp_loader}"
    echo "${count}"
}

echo "[$(date)] Starting rule update..."
mkdir -p "${BASE_DIR}"

echo "[*] Downloading GFWList..."
if ! wget -qO "${GFWLIST_FILE}" "${GFWLIST_URL}" 2>/dev/null; then
    echo "[!] Failed to download GFWList"
    touch "${GFWLIST_LUA}" 2>/dev/null || true
else
    echo "[*] Parsing GFWList..."
    decoded="${BASE_DIR}/gfwlist.decoded"
    >"${decoded}"
    base64 -d "${GFWLIST_FILE}" > "${decoded}" 2>/dev/null || \
        base64 -d -i "${GFWLIST_FILE}" > "${decoded}" 2>/dev/null || \
        openssl enc -base64 -d -in "${GFWLIST_FILE}" > "${decoded}" 2>/dev/null || true

    > "${GFWLIST_LUA}"
    count=0
    max=20000
    while IFS= read -r domain; do
        echo "gfwList:add(newDNSName(\"${domain}\"))" >> "${GFWLIST_LUA}"
        count=$((count + 1))
        [[ ${count} -ge ${max} ]] && break
    done < <(extract_domains_from_file "${decoded}")
    rm -f "${decoded}"
    echo "[+] GFWList: ${count} domains"
fi
append_local_gfwlist_extras

write_extra_list_lua "${PROXY_EXTRA_FILE}" "${CUSTOM_PROXY_LISTS_FILE}" "${PROXY_EXTRA_LUA}" "proxyExtraList" "proxy-extra"
write_extra_list_lua "${DIRECT_EXTRA_FILE}" "${CUSTOM_DIRECT_LISTS_FILE}" "${DIRECT_EXTRA_LUA}" "directExtraList" "direct-extra"

echo "[*] Downloading ChinaList..."
if ! wget -qO "${CHINALIST_FILE}" "${CHINALIST_URL}" 2>/dev/null; then
    echo "[!] Failed to download ChinaList"
    touch "${CHINALIST_LUA}" 2>/dev/null || true
else
    echo "[*] Parsing ChinaList..."
    tmp_chunk_dir=$(mktemp -d "${BASE_DIR}/chinalist.d.tmp.XXXXXX")
    tmp_loader=$(mktemp "${BASE_DIR}/chinalist.lua.tmp.XXXXXX")
    count=$(write_chinalist_chunks "${tmp_chunk_dir}" "${tmp_loader}")
    install_chinalist_chunks "${tmp_chunk_dir}" "${tmp_loader}"
    echo "[+] ChinaList: ${count} domains"
fi

if [[ ! -f "${DNSDIST_TEMPLATE}" ]]; then
    echo "[!] Template not found"
    exit 1
fi

echo "[*] Generating dnsdist configuration..."

SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+' || echo "127.0.0.1")
DOMAIN=$(cat "${BASE_DIR}/.domain" 2>/dev/null || echo "example.com")

CERT_BASENAME="${DOMAIN}"
if [[ -f "/opt/proxy-gateway/etc/.cert_basename" ]]; then
    CERT_BASENAME=$(cat "/opt/proxy-gateway/etc/.cert_basename")
fi
PRIVATE_OVERSEAS_DNS=$(cat "${BASE_DIR}/.overseas_private_dns" 2>/dev/null || cat "${BASE_DIR}/.overseas_dns" 2>/dev/null || echo "${DEFAULT_OVERSEAS_DNS[*]}")
PUBLIC_OVERSEAS_DNS=$(cat "${BASE_DIR}/.overseas_public_dns" 2>/dev/null || echo "${DEFAULT_PUBLIC_OVERSEAS_DNS[*]}")
OTHER_POLICY=$(cat "${BASE_DIR}/.other_policy" 2>/dev/null || echo "direct")
if [[ "$OTHER_POLICY" != "direct" && "$OTHER_POLICY" != "proxy" ]]; then
    echo "[!] Invalid OTHER_POLICY '${OTHER_POLICY}', using direct" >&2
    OTHER_POLICY="direct"
fi
DNS_CACHE_SIZE=$(cat "${BASE_DIR}/.cache_size" 2>/dev/null || echo "${DEFAULT_DNS_CACHE_SIZE}")
if [[ ! "$DNS_CACHE_SIZE" =~ ^[0-9]+$ || "$DNS_CACHE_SIZE" -lt 1 ]]; then
    echo "[!] Invalid DNS cache size '${DNS_CACHE_SIZE}', using ${DEFAULT_DNS_CACHE_SIZE}" >&2
    DNS_CACHE_SIZE="${DEFAULT_DNS_CACHE_SIZE}"
fi
OVERSEAS_PRIVATE_DNS_SERVERS=$(render_overseas_dns_servers "$PRIVATE_OVERSEAS_DNS" "overseas_private" "overseas_private")
OVERSEAS_PUBLIC_DNS_SERVERS=$(render_overseas_dns_servers "$PUBLIC_OVERSEAS_DNS" "overseas_public" "overseas_public")

python3 - "${DNSDIST_TEMPLATE}" "${GFWLIST_LUA}" "${CHINALIST_LUA}" "${PROXY_EXTRA_LUA}" "${DIRECT_EXTRA_LUA}" "${SERVER_IP}" "${CERT_BASENAME}" "${OVERSEAS_PRIVATE_DNS_SERVERS}" "${OVERSEAS_PUBLIC_DNS_SERVERS}" "${OTHER_POLICY}" "${DNS_CACHE_SIZE}" "${DNSDIST_CONF}" <<'PYEOF'
import sys
template_path = sys.argv[1]
gfw_path = sys.argv[2]
china_path = sys.argv[3]
proxy_extra_path = sys.argv[4]
direct_extra_path = sys.argv[5]
server_ip = sys.argv[6]
domain = sys.argv[7]
overseas_private_servers = sys.argv[8]
overseas_public_servers = sys.argv[9]
other_policy = sys.argv[10]
cache_size = sys.argv[11]
output_path = sys.argv[12]

def read_rules(path, fallback):
    with open(path, "r", encoding="utf-8") as f:
        rules = f.read().strip()
    return rules or fallback

with open(template_path, "r", encoding="utf-8") as f:
    content = f.read()
content = content.replace("__GFWLIST_RULES__", read_rules(gfw_path, "-- (no gfwlist rules loaded)"))
content = content.replace("__CHINALIST_RULES__", read_rules(china_path, "-- (no chinalist rules loaded)"))
content = content.replace("__PROXY_EXTRA_RULES__", read_rules(proxy_extra_path, "-- (no proxy-extra rules loaded)"))
content = content.replace("__DIRECT_EXTRA_RULES__", read_rules(direct_extra_path, "-- (no direct-extra rules loaded)"))
content = content.replace("__SERVER_IP__", server_ip)
content = content.replace("__DOMAIN__", domain)
content = content.replace("__OVERSEAS_PRIVATE_DNS_SERVERS__", overseas_private_servers)
content = content.replace("__OVERSEAS_PUBLIC_DNS_SERVERS__", overseas_public_servers)
content = content.replace("__OTHER_POLICY__", other_policy)
content = content.replace("__DNS_CACHE_SIZE__", cache_size)
with open(output_path, "w", encoding="utf-8") as f:
    f.write(content)
PYEOF

echo "[OK]   dnsdist configuration generated"

if command -v dnsdist >/dev/null 2>&1; then
    echo "[*] Validating dnsdist configuration..."
    if ! dnsdist --check-config -C "${DNSDIST_CONF}"; then
        echo "[!] Generated dnsdist configuration failed validation; leaving running dnsdist unchanged." >&2
        exit 1
    fi
    echo "[OK]   dnsdist configuration validated"
else
    echo "[!]    dnsdist binary not found; skipping config validation"
fi

ensure_dnsdist_active() {
    sleep 1
    if ! systemctl is-active --quiet dnsdist; then
        echo "[!]    dnsdist is not active after reload, restarting..."
        systemctl restart dnsdist
    fi
}

echo "[*] Reloading dnsdist..."
if systemctl is-active --quiet dnsdist; then
    if systemctl reload dnsdist 2>/dev/null; then
        echo "[OK]   dnsdist reloaded via systemd"
        ensure_dnsdist_active
    else
        echo "[!]    systemd reload failed, using SIGHUP..."
        DNSDIST_PID=$(pgrep -x dnsdist 2>/dev/null || true)
        if [[ -n "${DNSDIST_PID}" ]]; then
            kill -HUP "${DNSDIST_PID}" 2>/dev/null && echo "[OK]   dnsdist reloaded via SIGHUP"
            ensure_dnsdist_active
        else
            echo "[!]    Could not find dnsdist PID, restarting..."
            systemctl restart dnsdist
        fi
    fi
else
    systemctl start dnsdist
fi

echo "[$(date)] Rule update completed."
