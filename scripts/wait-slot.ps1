# Resource Sentinel - queue waiter
# A blocked session runs this to stay active while waiting for its turn.
# Exits 0 when: I am queue head AND a slot is free AND light is GREEN/YELLOW.
# The NEXT heavy command then acquires the slot in the gate (no race: only the
# head may acquire). Exits 1 on timeout. ASCII only.
param([int]$TimeoutSec = 480)
$ErrorActionPreference = 'SilentlyContinue'

$dataDir = Join-Path $env:USERPROFILE '.resource-sentinel'
$queuePath = Join-Path $dataDir 'queue.json'
$slotsPath = Join-Path $dataDir 'slots.json'
$statusPath = Join-Path $dataDir 'status.json'
$configPath = Join-Path $dataDir 'config.json'

$agentExes = @('claude.exe', 'cursor.exe', 'codex.exe')

function Get-AgentPid {
    $cur = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
    for ($i = 0; $i -lt 16; $i++) {
        if ($null -eq $cur) { break }
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($cur.ParentProcessId)"
        if ($null -eq $parent) { break }
        if ($agentExes -contains $parent.Name.ToLower()) { return [int]$parent.ProcessId }
        $cur = $parent
    }
    return [int]$cur.ParentProcessId
}

function Test-PidAlive([int]$p) {
    return $null -ne (Get-Process -Id $p -ErrorAction SilentlyContinue)
}

$me = Get-AgentPid
$capacity = 1
$cfg = Get-Content $configPath -Raw | ConvertFrom-Json
if ($null -ne $cfg.heavy_slots) { $capacity = [int]$cfg.heavy_slots }

$deadline = (Get-Date).AddSeconds($TimeoutSec)
Write-Output "waiting for heavy slot (agent pid $me, timeout ${TimeoutSec}s)..."

while ((Get-Date) -lt $deadline) {
    $status = Get-Content $statusPath -Raw | ConvertFrom-Json
    $light = if ($null -ne $status) { $status.light } else { 'GREEN' }

    $slots = @()
    $sd = Get-Content $slotsPath -Raw | ConvertFrom-Json
    if ($null -ne $sd) {
        $nowE = [double]((Get-Date).ToUniversalTime() - (Get-Date '1970-01-01')).TotalSeconds
        foreach ($s in @($sd.slots)) {
            if ($null -eq $s) { continue }
            $ttl = 15; if ($null -ne $s.ttl_min) { $ttl = [double]$s.ttl_min }
            if (($nowE - [double]$s.ts) -gt $ttl * 60) { continue }
            if (-not (Test-PidAlive([int]$s.pid))) { continue }
            $slots += $s
        }
    }

    $q = @()
    $qd = Get-Content $queuePath -Raw | ConvertFrom-Json
    if ($null -ne $qd) {
        $nowE = [double]((Get-Date).ToUniversalTime() - (Get-Date '1970-01-01')).TotalSeconds
        foreach ($e in @($qd.q)) {
            if ($null -eq $e) { continue }
            if (($nowE - [double]$e.ts) -gt 600) { continue }
            if (-not (Test-PidAlive([int]$e.pid))) { continue }
            if ([int]$e.pid -eq $me) { $e.ts = $nowE }   # refresh my entry
            $q += $e
        }
        # persist refreshed/cleaned queue (best effort, no lock: gate owns writes)
        $tmp = "$queuePath.tmp"
        (@{ q = $q } | ConvertTo-Json -Depth 3 -Compress) | Out-File $tmp -Encoding ascii
        Move-Item -Force $tmp $queuePath
    }

    $headOk = ($q.Count -eq 0) -or ([int]$q[0].pid -eq $me)
    $lightOk = ($light -eq 'GREEN' -or $light -eq 'YELLOW')
    if ($headOk -and $slots.Count -lt $capacity -and $lightOk) {
        Write-Output "your turn: slot free, light=$light. Re-run the heavy command NOW."
        exit 0
    }
    Start-Sleep -Seconds 5
}
Write-Output "timeout: still queued. Do light work and retry later."
exit 1
