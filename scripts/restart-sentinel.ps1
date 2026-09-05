# Manual recovery uses exactly the same ownership and verification rules as watchdog.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'collector-health.ps1')
try {
    $null = Restart-Collector (Join-Path $env:USERPROFILE '.resource-sentinel')
    Write-Output 'Resource Sentinel recovered: sample, publication, dashboard and completion advanced.'
} catch {
    Write-Error ('Recovery failed: ' + $_.Exception.Message)
    exit 1
}
