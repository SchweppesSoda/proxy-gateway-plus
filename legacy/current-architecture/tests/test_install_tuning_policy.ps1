$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$installPath = Join-Path $root "install.sh"
$install = Get-Content -Path $installPath -Raw -Encoding UTF8

function Assert-Contains {
    param(
        [string]$Needle,
        [string]$Description
    )

    if (-not $install.Contains($Needle)) {
        throw "Missing tuning marker: $Description ($Needle)"
    }
}

Assert-Contains 'net.core.default_qdisc=fq' 'fq queue discipline'
Assert-Contains 'net.core.somaxconn=10240000' 'large accept backlog'
Assert-Contains 'net.ipv4.tcp_fastopen=1027' 'aggressive TCP fast open'
Assert-Contains 'net.ipv4.tcp_rmem=8192 65536 134217728' 'large TCP receive buffer'
Assert-Contains 'net.ipv4.tcp_wmem=8192 131072 134217728' 'large TCP send buffer'
Assert-Contains 'net.netfilter.nf_conntrack_max=10240000' 'large conntrack table'
Assert-Contains 'disable-transparent-huge-pages.service' 'THP disable service'
Assert-Contains 'SystemMaxUse=384M' 'journald bounded disk usage'

Write-Output "install tuning markers OK"
