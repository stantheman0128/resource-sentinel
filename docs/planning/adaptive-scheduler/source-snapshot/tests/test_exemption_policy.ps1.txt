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
$script:io = 0
function Set-IoPriority($Process, $Level) { $script:io = $Level }
$demoted = @{ '123' = 'AboveNormal' }
Restore-SentinelExemptProcess $proc $demoted
Assert ($proc.PriorityClass -eq 'AboveNormal') 'Recorded CPU priority not restored'
Assert ($script:io -eq 2) 'I/O priority not restored'
Assert (-not $demoted.ContainsKey('123')) 'Demotion record not removed'
$proc.PriorityClass = 'BelowNormal'
Restore-SentinelExemptProcess $proc @{}
Assert ($proc.PriorityClass -eq 'Normal') 'Inherited demotion not restored'
$proc.PriorityClass = 'Idle'
Restore-SentinelExemptProcess $proc @{}
Assert ($proc.PriorityClass -eq 'Idle') 'Unrelated manual priority must be preserved'
foreach ($path in @('collect.ps1', 'invoke-sentinel.ps1', 'exemption-policy.ps1')) {
    $tokens = $null; $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot "../scripts/$path"), [ref]$tokens, [ref]$parseErrors) | Out-Null
    Assert ($parseErrors.Count -eq 0) "PowerShell parse failure: $path"
}
Write-Output 'Exemption collector policy: 9 assertions and 3 script parse checks passed.'
