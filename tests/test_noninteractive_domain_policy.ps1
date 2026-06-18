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
        throw "Missing noninteractive domain marker: $Description ($Needle)"
    }
}

Assert-Contains 'DOMAIN_PRECONFIGURED=1' 'preconfigured domain flag'
Assert-Contains 'verify_domain_dns()' 'generic DNS verification function'
Assert-Contains 'Pre-configured domain to verify and use for DoT/certificates' 'noninteractive domain help'
Assert-Contains 'Cloudflare' 'interactive custom DNS provider prompt'

Write-Output "noninteractive domain markers OK"
