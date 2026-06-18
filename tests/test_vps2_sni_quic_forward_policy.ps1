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
        throw "Missing VPS2 forward marker: $Description ($Needle)"
    }
}

Assert-Contains $install 'configure_vps1_forward_backend()' 'VPS1 forward configuration entrypoint'
Assert-Contains $install 'install_vps2_sni_quic_backend()' 'VPS2 SNI/QUIC backend entrypoint'
Assert-Contains $install 'stop_local_reverse_proxy_services()' 'VPS1 forward disables local reverse proxy services'
Assert-Contains $install 'systemctl disable sniproxy quic-proxy' 'VPS1 forward prevents local port conflicts'
Assert-Contains $install '.reverse_proxy_backend_ip' 'VPS2 backend IP is persisted'
Assert-Contains $install '.reverse_proxy_client_cidr' 'VPS1 client CIDR is persisted'
Assert-Contains $install 'dnat to "$backend_ip"' 'nft DNAT to VPS2 backend'
Assert-Contains $install 'masquerade' 'nft SNAT/MASQUERADE for backend return path'
Assert-Contains $install 'DNAT --to-destination "$backend_ip"' 'iptables DNAT to VPS2 backend'
Assert-Contains $install 'MASQUERADE' 'iptables SNAT/MASQUERADE for backend return path'
Assert-Contains $install 'setup_vps2_backend_firewall()' 'VPS2 backend firewall function'
Assert-Contains $install 'install_sniproxy' 'VPS2 backend installs sniproxy'
Assert-Contains $install 'install_quic_proxy' 'VPS2 backend installs quic-proxy'
Assert-Contains $install '--vps1-forward' 'VPS1 forward CLI option'
Assert-Contains $install '--vps2-backend' 'VPS2 backend CLI option'
Assert-Contains $readme './install.sh --vps1-forward' 'README documents VPS1 to VPS2 forward mode'

Write-Output "VPS2 SNI/QUIC forward markers OK"
