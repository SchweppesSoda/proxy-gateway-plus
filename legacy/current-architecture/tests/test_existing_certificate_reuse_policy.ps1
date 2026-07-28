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
        throw "Missing certificate reuse marker: $Description ($Needle)"
    }
}

function Assert-NotContains {
    param(
        [string]$Haystack,
        [string]$Needle,
        [string]$Description
    )

    if ($Haystack.Contains($Needle)) {
        throw "Unexpected certificate reuse marker: $Description ($Needle)"
    }
}

Assert-Contains $install 'find_existing_cert_for_domain()' 'existing certificate discovery function'
Assert-Contains $install 'cert_covers_domain()' 'certificate host validation function'
Assert-Contains $install '-checkhost "$domain"' 'OpenSSL host check'
Assert-Contains $install '-checkend 604800' 'certificate expiry guard'
Assert-Contains $install 'find_existing_cert_for_domain "$DOMAIN"' 'installer checks for reusable cert before certbot'
Assert-Contains $install 'copy_cert_to_dnsdist "$existing_cert_dir"' 'installer copies reusable cert to dnsdist'
Assert-Contains $install 'deploy_cert_renewal_hook' 'renewal hook is installed for reused certs'
Assert-NotContains $install 'certbot_cmd_force' 'normal install must not force renew existing certificates'
Assert-Contains $readme 'existing certificate' 'README documents existing certificate reuse'

Write-Output "existing certificate reuse markers OK"
