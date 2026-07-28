$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$templatePath = Join-Path $root "dnsdist.conf.template"
$installPath = Join-Path $root "install.sh"
$template = Get-Content -Path $templatePath -Raw -Encoding UTF8
$install = Get-Content -Path $installPath -Raw -Encoding UTF8

function Assert-Contains {
    param(
        [string]$Needle,
        [string]$Description
    )

    if (-not $template.Contains($Needle)) {
        throw "Missing DNS performance marker: $Description ($Needle)"
    }
}

Assert-Contains 'setServerPolicy(leastOutstanding)' 'least outstanding server policy'
Assert-Contains 'sessionTickets=true' 'DoT TLS session tickets'
Assert-Contains 'sessionTimeout=3600' 'DoT TLS session timeout'
Assert-Contains 'newPacketCache(__DNS_CACHE_SIZE__' 'configurable packet cache'
Assert-Contains 'minTTL=300' 'higher minimum cache TTL'
Assert-Contains 'temporaryFailureTTL=60' 'temporary failure cache TTL'
Assert-Contains 'staleTTL=300' 'stale cache TTL'

if (-not $install.Contains('DEFAULT_DNS_CACHE_SIZE=200000')) {
    throw "Missing low-memory default cache size marker"
}

Write-Output "DNS performance markers OK"
