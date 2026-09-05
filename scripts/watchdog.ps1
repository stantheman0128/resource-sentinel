# Resource Sentinel - watchdog (reverse monitor for the collector)
# Separate scheduled task, every 5 min. If status.json is stale: try to restart
# the collector task; if still stale, send a Telegram alert (Chinese templates).
# Never touches anything else. ASCII only.
$ErrorActionPreference = 'Stop'

$dataDir = Join-Path $env:USERPROFILE '.resource-sentinel'
$statusPath = Join-Path $dataDir 'status.json'
$configPath = Join-Path $dataDir 'config.json'
$wdStatePath = Join-Path $dataDir 'watchdog-state.json'

function Get-AgeMin {
    try {
        $s = Get-Content $statusPath -Raw | ConvertFrom-Json
        $gen = [datetime]::ParseExact($s.generated_at, 'yyyy-MM-dd HH:mm:ss', $null)
        return [math]::Round(((Get-Date) - $gen).TotalMinutes, 0)
    } catch { return 9999 }
}

function Send-Tg([string]$text) {
    $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
    if ($null -eq $cfg.telegram -or -not $cfg.telegram.enabled) { return }
    $token = $null; $chat = $null
    foreach ($ln in (Get-Content $cfg.telegram.env_path)) {
        if ($ln -match '^TELEGRAM_BOT_TOKEN=(.+)$') { $token = $Matches[1].Trim() }
        if ($ln -match '^TELEGRAM_ALLOWED_IDS=(.+)$') { $chat = $Matches[1].Split(',')[0].Trim() }
    }
    if ($null -ne $cfg.telegram.chat_id) { $chat = [string]$cfg.telegram.chat_id }
    if ($token -and $chat) {
        $body = "chat_id=$chat&text=" + [uri]::EscapeDataString($text)
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$token/sendMessage" `
            -Method Post -TimeoutSec 8 `
            -ContentType 'application/x-www-form-urlencoded; charset=utf-8' `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) | Out-Null
    }
}

# A separate mutex also protects manual watchdog invocations and cooldown writes.
. (Join-Path $PSScriptRoot 'collector-health.ps1')
$lock = New-Object System.Threading.Mutex($false, 'Local\ResourceSentinelWatchdog')
$held = $false
try {
    try { $held = $lock.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $held = $true }
    if (-not $held) { exit 0 }
    if ((Get-CollectorHealth $dataDir).Healthy) { exit 0 }
    $wd = @{ last_alert = [double]0; last_restart = [double]0; failures = 0; outcome = 'unknown' }
    try {
        $saved = Get-Content $wdStatePath -Raw -ErrorAction Stop | ConvertFrom-Json
        foreach ($key in @('last_alert', 'last_restart', 'failures', 'outcome')) {
            if ($null -ne $saved.$key) { $wd[$key] = $saved.$key }
        }
    } catch { }
    $nowE = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    # At most one attempt per 10 min; after 3 failures, back off to one per hour.
    $cooldown = if ($wd.failures -ge 3) { 3600 } else { 600 }
    if (($nowE - $wd.last_restart) -lt $cooldown) { exit 0 }
    # Recheck immediately before initiating recovery.
    if ((Get-CollectorHealth $dataDir).Healthy) { exit 0 }
    $wd.last_restart = $nowE
    $wd.outcome = 'attempting'
    function Save-WatchdogState {
        $wd | ConvertTo-Json -Compress | Set-Content -LiteralPath "$wdStatePath.tmp" -Encoding ascii -ErrorAction Stop
        Move-Item -LiteralPath "$wdStatePath.tmp" -Destination $wdStatePath -Force -ErrorAction Stop
    }
    Save-WatchdogState
    $age = Get-AgeMin
    try {
        $null = Restart-Collector $dataDir
        $wd.outcome = 'recovered'
        $wd.reason = 'verified'
        $wd.failures = 0
    } catch {
        $wd.outcome = 'recovery_failed'
        $reason = $_.Exception.Message
        $knownReasons = @('CollectorRecoveryBusy', 'CollectorTaskDisabled', 'CollectorStopTimeout', 'CollectorStillActive', 'CollectorRecoveryUnverified')
        $wd.reason = if ($knownReasons -contains $reason) { $reason } else { $_.Exception.GetType().Name }
        $wd.failures = [int]$wd.failures + 1
    }
    Save-WatchdogState
    $logPath = Join-Path $dataDir 'watchdog-events.log'
    if ((Test-Path $logPath) -and (Get-Item $logPath).Length -gt 256KB) {
        $tail = @(Get-Content $logPath -Tail 100)
        $tail | Set-Content $logPath
    }
    ('{0:o} outcome={1} failures={2} reason={3}' -f (Get-Date), $wd.outcome, $wd.failures, $wd.reason) | Add-Content $logPath
    if (($nowE - $wd.last_alert) -gt 3600) {
        $tpl = Get-Content (Join-Path $PSScriptRoot 'messages.json') -Raw | ConvertFrom-Json
        $message = if ($wd.outcome -eq 'recovered') { $tpl.watchdog_revived } else { $tpl.watchdog_dead }
        if ($message) {
            Send-Tg $message.Replace('{age}', [string]$age)
            $wd.last_alert = $nowE
            Save-WatchdogState
        }
    }
    if ($wd.outcome -ne 'recovered') { exit 1 }
} finally {
    if ($held) { $lock.ReleaseMutex() }
    $lock.Dispose()
}
