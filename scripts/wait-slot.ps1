# Resource Sentinel - atomic queue waiter.
# The coordinator grants the reservation before this script prints "your turn".
param(
    [int]$TimeoutSec = 480,
    [string]$RequestId = ''
)
$ErrorActionPreference = 'Stop'

$dataDir = Join-Path $env:USERPROFILE '.resource-sentinel'
$statusPath = Join-Path $dataDir 'status.json'
$configPath = Join-Path $dataDir 'config.json'
$ctl = Join-Path $PSScriptRoot 'sentinelctl.py'
$agentExes = @('claude.exe', 'cursor.exe', 'codex.exe', 'chatgpt.exe')

function Get-AgentPid {
    try {
        $cur = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
        for ($i = 0; $i -lt 32; $i++) {
            if ($null -eq $cur) { break }
            $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($cur.ParentProcessId)"
            if ($null -eq $parent) { break }
            if ($agentExes -contains $parent.Name.ToLower()) { return [int]$parent.ProcessId }
            $cur = $parent
        }
    } catch { }
    return [int]$PID
}

$ownerPid = Get-AgentPid
$argsList = @(
    $ctl, '--data-dir', $dataDir, 'wait-existing',
    '--status-file', $statusPath, '--config-file', $configPath,
    '--timeout-sec', [string]$TimeoutSec
)
if ($RequestId) {
    $argsList += @('--request-key', $RequestId)
} else {
    $argsList += @('--owner-pid', [string]$ownerPid)
}

Write-Output "waiting for atomic reservation (agent pid $ownerPid, timeout ${TimeoutSec}s)..."
& py @argsList
if ($LASTEXITCODE -eq 0) {
    Write-Output 'your turn: reservation acquired. Re-run the heavy command NOW.'
    exit 0
}
Write-Output 'timeout or request missing. Do light work and retry later.'
exit 1
