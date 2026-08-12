# Resource Sentinel - watchdog (reverse monitor for the collector)
# Separate scheduled task, every 5 min. If status.json is stale: try to restart
# the collector task; if still stale, send a Telegram alert (Chinese templates).
# Never touches anything else. ASCII only.
$ErrorActionPreference = 'SilentlyContinue'

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

$age = Get-AgeMin
if ($age -le 5) { exit 0 }   # collector healthy

# stale: try to revive once
schtasks /run /tn "ResourceSentinel" | Out-Null
Start-Sleep -Seconds 75
$age2 = Get-AgeMin

# alert cooldown 60 min
$wd = @{ last_alert = [double]0 }
try {
    $j = Get-Content $wdStatePath -Raw | ConvertFrom-Json
    if ($null -ne $j.last_alert) { $wd.last_alert = [double]$j.last_alert }
} catch { }
$nowE = [double]((Get-Date).ToUniversalTime() - (Get-Date '1970-01-01')).TotalSeconds
$canAlert = ($nowE - $wd.last_alert) -gt 3600

$tpl = Get-Content (Join-Path $PSScriptRoot 'messages.json') -Raw | ConvertFrom-Json
if ($age2 -le 5) {
    if ($canAlert -and $null -ne $tpl) {
        Send-Tg $tpl.watchdog_revived.Replace('{age}', [string]$age)
        $wd.last_alert = $nowE
    }
} else {
    if ($canAlert -and $null -ne $tpl) {
        Send-Tg $tpl.watchdog_dead.Replace('{age}', [string]$age2)
        $wd.last_alert = $nowE
    }
}
$tmp = "$wdStatePath.tmp"
(@{ last_alert = $wd.last_alert } | ConvertTo-Json -Compress) | Out-File $tmp -Encoding ascii
Move-Item -Force $tmp $wdStatePath
