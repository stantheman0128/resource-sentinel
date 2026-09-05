# Shared read-only health check and bounded recovery. No process-name killing.
function Get-CollectorHealth([string]$DataDir) {
    try {
        $s = Get-Content -LiteralPath (Join-Path $DataDir 'status.json') -Raw -ErrorAction Stop | ConvertFrom-Json
        $p = Get-Content -LiteralPath (Join-Path $DataDir 'collector-progress.json') -Raw -ErrorAction Stop | ConvertFrom-Json
        $generated = [datetime]::ParseExact($s.generated_at, 'yyyy-MM-dd HH:mm:ss', $null)
        $sampled = [datetime]::ParseExact($s.sampled_at, 'yyyy-MM-dd HH:mm:ss', $null)
        $completed = [datetime]::Parse($p.last_completed_at)
        $dashboard = (Get-Item -LiteralPath (Join-Path $DataDir 'data.js') -ErrorAction Stop).LastWriteTime
        $now = Get-Date
        $healthy = $true
        foreach ($stamp in @($generated, $sampled, $completed, $dashboard)) {
            $age = ($now - $stamp).TotalSeconds
            if ($age -lt -30 -or $age -gt 300) { $healthy = $false }
        }
        return [pscustomobject]@{ Healthy = $healthy; Generated = $generated; Sampled = $sampled; Completed = $completed; Dashboard = $dashboard }
    } catch {
        return [pscustomobject]@{ Healthy = $false; Generated = [datetime]::MinValue; Sampled = [datetime]::MinValue; Completed = [datetime]::MinValue; Dashboard = [datetime]::MinValue }
    }
}

function Restart-Collector([string]$DataDir, [string]$MutexName = 'Local\ResourceSentinelScheduledCollector', [int]$VerifyTimeoutSec = 75) {
    $before = Get-CollectorHealth $DataDir
    # The runner owns this mutex until its child has exited (45-second bound).
    # Never stop a launcher while an active collector/dispatch could be orphaned.
    $mutex = New-Object System.Threading.Mutex($false, $MutexName)
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne(85000) }
        catch [System.Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'CollectorRecoveryBusy' }
        # A forcibly terminated runner can abandon its mutex but leave a child.
        $progressPath = Join-Path $DataDir 'collector-progress.json'
        if (Test-Path -LiteralPath $progressPath) {
            $progress = Get-Content -LiteralPath $progressPath -Raw -ErrorAction Stop | ConvertFrom-Json
            $live = Get-Process -Id ([int]$progress.pid) -ErrorAction SilentlyContinue
            if ($live -and $live.StartTime.ToString('o') -eq $progress.process_started_at) {
                throw 'CollectorStillActive'
            }
        }
        $task = Get-ScheduledTask -TaskName 'ResourceSentinel' -ErrorAction Stop
        if ($task.State -eq 'Disabled') { throw 'CollectorTaskDisabled' }
        Stop-ScheduledTask -TaskName 'ResourceSentinel' -ErrorAction Stop
        $stopDeadline = (Get-Date).AddSeconds(10)
        while ((Get-ScheduledTask -TaskName 'ResourceSentinel' -ErrorAction Stop).State -eq 'Running') {
            if ((Get-Date) -ge $stopDeadline) { throw 'CollectorStopTimeout' }
            Start-Sleep -Milliseconds 250
        }
    } finally {
        if ($acquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
    Start-ScheduledTask -TaskName 'ResourceSentinel' -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds($VerifyTimeoutSec)
    do {
        Start-Sleep -Seconds 3
        $after = Get-CollectorHealth $DataDir
        if ($after.Healthy -and $after.Generated -gt $before.Generated -and
            $after.Sampled -gt $before.Sampled -and $after.Completed -gt $before.Completed -and
            $after.Dashboard -gt $before.Dashboard) { return $true }
    } while ((Get-Date) -lt $deadline)
    throw 'CollectorRecoveryUnverified'
}
