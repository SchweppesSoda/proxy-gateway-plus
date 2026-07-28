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
        throw "Missing reverse proxy firewall marker: $Description ($Needle)"
    }
}

Assert-Contains $install 'DEFAULT_FIREWALL_MODE="additive"' 'additive firewall is default'
Assert-Contains $install 'detect_ssh_ports()' 'actual SSH port detection'
Assert-Contains $install 'sshd -T' 'sshd effective config probe'
Assert-Contains $install '/etc/ssh/sshd_config.d/*.conf' 'sshd include directory probe'
Assert-Contains $install 'SSH_CONNECTION' 'current SSH session port preservation'
Assert-Contains $install 'proxy_gateway_filter' 'nft additive filter chain'
Assert-Contains $install 'PROXY_GATEWAY_INPUT' 'iptables additive input chain'
Assert-Contains $install 'managed-exclusive' 'explicit managed firewall mode'
Assert-Contains $install 'ip saddr "$client_cidr" tcp dport { 80, 443 } accept' 'nft TCP reverse proxy private allow'
Assert-Contains $install 'ip saddr "$client_cidr" udp dport 443 accept' 'nft UDP reverse proxy private allow'
Assert-Contains $install 'iptables -A PROXY_GATEWAY_INPUT -s "$client_cidr" -p tcp -m multiport --dports 80,443 -j ACCEPT' 'iptables TCP reverse proxy private allow'
Assert-Contains $install 'iptables -A PROXY_GATEWAY_INPUT -s "$client_cidr" -p udp --dport 443 -j ACCEPT' 'iptables UDP reverse proxy private allow'
Assert-Contains $install '--comment proxy-gateway-cert-http' 'temporary HTTP rule is tagged'
Assert-Contains $install 'open_cert_http_port()' 'cert flow opens HTTP-01 port temporarily'
Assert-Contains $install 'restore_reverse_proxy_firewall()' 'cert flow restores reverse proxy whitelist'
Assert-Contains $install '--pre-hook /usr/local/bin/proxy-gateway-open-cert-http.sh' 'certbot pre-hook opens port 80'
Assert-Contains $install '--post-hook /usr/local/bin/proxy-gateway-restore-firewall.sh' 'certbot post-hook restores firewall'
Assert-Contains $install '/etc/letsencrypt/renewal-hooks/pre/10-proxy-gateway-open-http.sh' 'automatic renew pre-hook'
Assert-Contains $install '/etc/letsencrypt/renewal-hooks/post/90-proxy-gateway-restore-firewall.sh' 'automatic renew post-hook'
Assert-Contains $install 'Firewall configured (mode:' 'firewall status message'
Assert-Contains $readme '172.22.0.0/16' 'README documents reverse proxy whitelist'
Assert-Contains $readme '80/443' 'README documents reverse proxy ports'
Assert-Contains $readme '443' 'README documents reverse proxy port'

Write-Output "reverse proxy firewall markers OK"
