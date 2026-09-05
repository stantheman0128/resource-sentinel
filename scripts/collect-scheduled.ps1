# Task Scheduler starts this bounded runner once per minute.
# Collections target :00/:30. Skip missed slots instead of overlapping/catching up.
$ErrorActionPreference = 'Stop'
$collector = Join-Path $PSScriptRoot 'collect.ps1'
$mutex = New-Object System.Threading.Mutex($false, 'Local\ResourceSentinelScheduledCollector')
$acquired = $false
try {
    try { $acquired = $mutex.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $acquired = $true }
    if (-not $acquired) { return }
    $started = Get-Date
    $minute = $started.Date.AddHours($started.Hour).AddMinutes($started.Minute)
    $deadline = $minute.AddMinutes(1)
    foreach ($offset in @(0, 30)) {
        $slot = $minute.AddSeconds($offset)
        $current = Get-Date
        if ($current -ge $deadline -or ($current - $slot).TotalSeconds -gt 5) { continue }
        $delay = ($slot - $current).TotalMilliseconds
        if ($delay -gt 0) { Start-Sleep -Milliseconds ([int][math]::Ceiling($delay)) }
        try { & $collector }
        catch { Write-Warning ('Collector failed: ' + $_.Exception.GetType().Name) }
    }
} finally {
    if ($acquired) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
