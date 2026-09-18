$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts\collector-health.ps1')
. (Join-Path $root 'scripts\bounded-query.ps1')
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
$temp = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-recovery-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temp
try {
    Assert (-not (Get-CollectorHealth $temp).Healthy) 'Missing data must be unhealthy'
    $stamp = (Get-Date).AddSeconds(-10).ToString('yyyy-MM-dd HH:mm:ss')
    @{ generated_at = $stamp; sampled_at = $stamp } | ConvertTo-Json | Set-Content "$temp\status.json"
    @{ last_completed_at = $stamp } | ConvertTo-Json | Set-Content "$temp\collector-progress.json"
    'data' | Set-Content "$temp\data.js"
    Assert (Get-CollectorHealth $temp).Healthy 'Fresh data should be healthy'
    (Get-Item "$temp\data.js").LastWriteTime = (Get-Date).AddMinutes(-6)
    Assert (-not (Get-CollectorHealth $temp).Healthy) 'Stale dashboard must fail'
    (Get-Item "$temp\data.js").LastWriteTime = Get-Date
    @{ last_completed_at = (Get-Date).AddMinutes(-6).ToString('o') } | ConvertTo-Json | Set-Content "$temp\collector-progress.json"
    Assert (-not (Get-CollectorHealth $temp).Healthy) 'Fresh publication must not hide stuck tail stages'
    @{ last_completed_at = $stamp } | ConvertTo-Json | Set-Content "$temp\collector-progress.json"
    @{ generated_at = $stamp; sampled_at = (Get-Date).AddMinutes(-6).ToString('yyyy-MM-dd HH:mm:ss') } | ConvertTo-Json | Set-Content "$temp\status.json"
    Assert (-not (Get-CollectorHealth $temp).Healthy) 'Stale sample must fail'
    @{ generated_at = (Get-Date).AddMinutes(10).ToString('yyyy-MM-dd HH:mm:ss'); sampled_at = $stamp } | ConvertTo-Json | Set-Content "$temp\status.json"
    Assert (-not (Get-CollectorHealth $temp).Healthy) 'Future timestamp must fail'
    'broken' | Set-Content "$temp\status.json"
    Assert (-not (Get-CollectorHealth $temp).Healthy) 'Malformed status must fail'

    $out = Invoke-BoundedQuery (Join-Path $PSHOME 'powershell.exe') '-NoProfile -Command "Write-Output probe-ok"' 5000
    Assert ($out -eq 'probe-ok') 'Probe output should be returned'
    $timedOut = $false
    try { Invoke-BoundedQuery (Join-Path $PSHOME 'powershell.exe') '-NoProfile -Command "Start-Sleep -Seconds 10"' 250 }
    catch { $timedOut = $_.Exception.Message -eq 'OptionalProbeTimeout' }
    Assert $timedOut 'Hung optional probe must time out'

    # Scheduler calls and sleep are mocked; no production task is touched.
    Remove-Item -LiteralPath "$temp\collector-progress.json"
    $script:calls = @()
    $script:mode = 'advance'
    $script:reads = 0
    function Get-CollectorHealth($DataDir) {
        $script:reads++
        $t = [datetime]'2026-01-01'
        if ($script:reads -gt 1 -and $script:mode -eq 'advance') { $t = $t.AddSeconds(30) }
        return [pscustomobject]@{ Healthy = $true; Generated = $t; Sampled = $t; Completed = $t; Dashboard = $t }
    }
    function Get-ScheduledTask { param($TaskName, $ErrorAction) return [pscustomobject]@{State = 'Ready'} }
    function Stop-ScheduledTask { param($TaskName, $ErrorAction) $script:calls += 'stop' }
    function Start-ScheduledTask { param($TaskName, $ErrorAction) $script:calls += 'start' }
    function Start-Sleep { param($Seconds, $Milliseconds) }
    Assert (Restart-Collector $temp ('Local\SentinelTest' + [guid]::NewGuid().ToString('N')) 0) 'Advanced timestamps should verify recovery'
    Assert (($script:calls -join ',') -eq 'stop,start') 'Recovery must stop before start'
    $script:mode = 'unchanged'; $script:reads = 0
    $failed = $false
    try { Restart-Collector $temp ('Local\SentinelTest' + [guid]::NewGuid().ToString('N')) 0 }
    catch { $failed = $_.Exception.Message -eq 'CollectorRecoveryUnverified' }
    Assert $failed 'Task start without advancing data must fail'
    $script:calls = @()
    @{ pid = $PID; process_started_at = (Get-Process -Id $PID).StartTime.ToString('o') } | ConvertTo-Json | Set-Content "$temp\collector-progress.json"
    $failed = $false
    try { Restart-Collector $temp ('Local\SentinelTest' + [guid]::NewGuid().ToString('N')) 0 }
    catch { $failed = $_.Exception.Message -eq 'CollectorStillActive' }
    Assert ($failed -and $script:calls.Count -eq 0) 'Live orphan must prevent stop/start'
    Remove-Item -LiteralPath "$temp\collector-progress.json"
    function Get-ScheduledTask { param($TaskName, $ErrorAction) return [pscustomobject]@{State = 'Disabled'} }
    $failed = $false
    try { Restart-Collector $temp ('Local\SentinelTest' + [guid]::NewGuid().ToString('N')) 0 }
    catch { $failed = $_.Exception.Message -eq 'CollectorTaskDisabled' }
    Assert ($failed -and $script:calls.Count -eq 0) 'Disabled task must not be enabled by recovery'
    Write-Output 'PASS: health, partial publication, stale/future/malformed data, optional probe timeout, recovery order and verification'
} finally {
    # Delete only this test-created directory, after resolving and checking its parent.
    $resolved = [IO.Path]::GetFullPath($temp)
    $base = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ($resolved.StartsWith($base) -and (Split-Path $resolved -Leaf).StartsWith('sentinel-recovery-test-')) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
