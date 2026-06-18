$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$template = Get-Content -Path (Join-Path $root "dnsdist.conf.template") -Raw -Encoding UTF8
$install = Get-Content -Path (Join-Path $root "install.sh") -Raw -Encoding UTF8
$rules = Get-Content -Path (Join-Path $root "update-rules.sh") -Raw -Encoding UTF8
$readme = Get-Content -Path (Join-Path $root "README.md") -Raw -Encoding UTF8

function Assert-Contains {
    param(
        [string]$Haystack,
        [string]$Needle,
        [string]$Description
    )

    if (-not $Haystack.Contains($Needle)) {
        throw "Missing DNS policy marker: $Description ($Needle)"
    }
}

Assert-Contains $template 'local proxyExtraList = newSuffixMatchNode()' 'proxy extra suffix tree'
Assert-Contains $template 'local directExtraList = newSuffixMatchNode()' 'direct extra suffix tree'
Assert-Contains $template '__PROXY_EXTRA_RULES__' 'proxy extra placeholder'
Assert-Contains $template '__DIRECT_EXTRA_RULES__' 'direct extra placeholder'
Assert-Contains $template 'local otherPolicy = "__OTHER_POLICY__"' 'other policy placeholder'
Assert-Contains $template 'return otherPolicy == "proxy"' 'other policy proxy spoof'

Assert-Contains $rules 'PROXY_EXTRA_FILE="${BASE_DIR}/proxy-extra-local.txt"' 'proxy local file'
Assert-Contains $rules 'DIRECT_EXTRA_FILE="${BASE_DIR}/direct-extra-local.txt"' 'direct local file'
Assert-Contains $rules 'CUSTOM_PROXY_LISTS_FILE="${BASE_DIR}/custom-proxy-lists.txt"' 'custom proxy URL list'
Assert-Contains $rules 'CUSTOM_DIRECT_LISTS_FILE="${BASE_DIR}/custom-direct-lists.txt"' 'custom direct URL list'
Assert-Contains $rules 'write_extra_list_lua "${PROXY_EXTRA_FILE}" "${CUSTOM_PROXY_LISTS_FILE}"' 'proxy list generation'
Assert-Contains $rules 'write_extra_list_lua "${DIRECT_EXTRA_FILE}" "${CUSTOM_DIRECT_LISTS_FILE}"' 'direct list generation'

Assert-Contains $install 'configure_dns_policy()' 'interactive DNS policy function'
Assert-Contains $install 'configure_custom_lists_menu()' 'custom list menu'
Assert-Contains $install 'clear_settings_menu()' 'clear DNS settings menu'
Assert-Contains $install '--clear-settings' 'clear DNS settings CLI option'
Assert-Contains $install 'main_menu()' 'main menu function'
Assert-Contains $install 'Proxy Gateway Plus' 'main menu title'
Assert-Contains $install 'VPS1 -> VPS2 SNI/QUIC' 'main menu groups VPS1 forwarding task'
Assert-Contains $install 'sniproxy + quic-proxy' 'main menu identifies VPS2 backend services'
Assert-Contains $install '0-14' 'main menu input range'
Assert-Contains $install 'DNS_CACHE_SIZE' 'cache size configuration'
Assert-Contains $install 'DOMAIN-SUFFIX' 'custom list menu explains unsupported formats'
Assert-Contains $readme 'server=/example.com/1.1.1.1' 'README documents accepted custom rule formats'
Assert-Contains $readme 'DOMAIN-SUFFIX,example.com,Proxy' 'README documents unsupported custom rule formats'

Write-Output "DNS policy extensibility markers OK"
