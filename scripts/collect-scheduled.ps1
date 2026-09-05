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
        # Always attempt one collection after a delayed start; only skip late second slots.
        if ($offset -ne 0 -and ($current -ge $deadline -or ($current - $slot).TotalSeconds -gt 5)) { continue }
        $delay = ($slot - $current).TotalMilliseconds
        if ($delay -gt 0) { Start-Sleep -Milliseconds ([int][math]::Ceiling($delay)) }
        try {
            $child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $collector + '"')
            ) -WindowStyle Hidden -PassThru
            try {
                if (-not $child.WaitForExit(45000)) {
                    & taskkill.exe /PID $child.Id /T /F | Out-Null
                    throw [TimeoutException]::new('Collector exceeded 45 seconds')
                }
                $child.WaitForExit()
                if ($child.ExitCode -ne 0) { throw 'Collector exited unsuccessfully' }
            } finally { $child.Dispose() }
        }
        catch {
            $failureLog = Join-Path $env:USERPROFILE '.resource-sentinel\collector-errors.log'
            if ((Test-Path $failureLog) -and (Get-Item $failureLog).Length -gt 256KB) {
                $tail = @(Get-Content $failureLog -Tail 100)
                $tail | Set-Content $failureLog
            }
            # Log error type and source line only; never raw command/output or secrets.
            ('{0:o} {1} line={2}' -f (Get-Date), $_.Exception.GetType().Name,
                $_.InvocationInfo.ScriptLineNumber) | Add-Content $failureLog
            throw
        }
    }
} finally {
    if ($acquired) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
