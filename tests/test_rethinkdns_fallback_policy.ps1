$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$install = Get-Content -Path (Join-Path $root "install.sh") -Raw -Encoding UTF8
$readme = Get-Content -Path (Join-Path $root "README.md") -Raw -Encoding UTF8

function Assert-Contains {
    param(
        [string]$Haystack,
        [string]$Needle,
        [string]$Description
    )

    if (-not $Haystack.Contains($Needle)) {
        throw "Missing fallback marker: $Description ($Needle)"
    }
}

Assert-Contains $install 'install_wireguard_fallback()' 'WireGuard fallback function'
Assert-Contains $install 'wireguard-tools' 'native WireGuard tooling'
Assert-Contains $install 'wg-quick@pgw-rdns' 'WireGuard systemd service'
Assert-Contains $install 'install_socks5_fallback()' 'SOCKS5 fallback function'
Assert-Contains $install 'find_singbox_candidate()' 'sing-box detection function'
Assert-Contains $install '${home_dir}/agsbx/sing-box' 'argosbx sing-box binary path'
Assert-Contains $install '${home_dir}/agsbx/sb.json' 'argosbx sing-box config path'
Assert-Contains $install 'proxy-gateway-socks-in' 'proxy-gateway SOCKS inbound tag'
Assert-Contains $install 'backup_config=' 'existing sing-box backup before reuse'
Assert-Contains $install 'proxy-gateway-socks.service' 'independent SOCKS service fallback'
Assert-Contains $install 'setup_socks_only_firewall()' 'VPS2 SOCKS-only firewall'
Assert-Contains $install 'https://sing-box.app/install.sh -o "$installer"' 'download sing-box installer before running'

Assert-Contains $readme 'RethinkDNS' 'README documents RethinkDNS'
Assert-Contains $readme 'WireGuard' 'README documents WireGuard fallback'
Assert-Contains $readme 'SOCKS5' 'README documents SOCKS5 fallback'
Assert-Contains $readme 'add-on fallback' 'README describes fallback as an add-on'

Write-Output "RethinkDNS fallback markers OK"
