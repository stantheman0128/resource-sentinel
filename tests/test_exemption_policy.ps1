$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/exemption-policy.ps1')
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
$epoch = [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
$proc = [pscustomobject]@{ Id = 123; StartTime = $epoch.AddSeconds(10); PriorityClass = 'BelowNormal' }
$rows = @{ '123' = @{ started = 10; expires_at = 100 } }
Assert (Test-SentinelExemption $proc $rows 99) 'Live grant not recognized'
Assert (-not (Test-SentinelExemption $proc $rows 100)) 'Expiry must restore normal guards'
$proc.StartTime = $epoch.AddSeconds(11)
Assert (-not (Test-SentinelExemption $proc $rows 99)) 'Reused PID must not inherit exemption'
$proc.StartTime = $epoch.AddSeconds(10)
Assert (-not (Test-SentinelExemption $proc @{} 99)) 'Revoked grant must not match'
# The legacy direct setter is intentionally replaced by a read-only intent.
# Only the guarded mutation adapter may apply it and acknowledge record cleanup.
$demoted = @{ '123' = 'AboveNormal' }
$intent = Get-SentinelExemptRestoreIntent $proc $demoted
Assert ($intent.priority_action -eq 'restore' -and $intent.restore_priority -eq 'AboveNormal') 'Recorded priority must become a restore intent'
Assert ($intent.io_priority -eq 2 -and $intent.trim -eq $false) 'Restore intent must request normal I/O without trimming'
Assert ($proc.PriorityClass -eq 'BelowNormal') 'Building an intent must not change process priority'
Assert ($demoted.ContainsKey('123') -and $demoted['123'] -eq 'AboveNormal') 'Building an intent must retain the demotion record'
$intent = Get-SentinelExemptRestoreIntent $proc @{}
Assert ($intent.restore_priority -eq 'Normal') 'Unrecorded restore intent must use the legacy Normal target'
Assert ($proc.PriorityClass -eq 'BelowNormal') 'Unrecorded intent must not apply its target'
$proc.PriorityClass = 'Idle'
$intent = Get-SentinelExemptRestoreIntent $proc @{}
Assert ($proc.PriorityClass -eq 'Idle') 'Unrelated manual priority must be preserved'
foreach ($path in @('collect.ps1', 'invoke-sentinel.ps1', 'exemption-policy.ps1')) {
    $tokens = $null; $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot "../scripts/$path"), [ref]$tokens, [ref]$parseErrors) | Out-Null
    Assert ($parseErrors.Count -eq 0) "PowerShell parse failure: $path"
}
Write-Output 'Exemption policy: identity/expiry, read-only restore intents, and script parse checks passed.'
