# Reserve local capacity, run one command, and always release the reservation.
param(
    [Parameter(Mandatory = $true)][string]$Command,
    [ValidateSet('AUTO', 'LIGHT', 'MEDIUM', 'HEAVY', 'EXTREME')][string]$ResourceClass = 'AUTO',
    [ValidateSet('P0', 'P1', 'P2', 'P3')][string]$Priority = 'P2',
    [int]$TimeoutSec = 1800,
    [string]$Repo = ''
)
$ErrorActionPreference = 'Stop'

$dataDir = Join-Path $env:USERPROFILE '.resource-sentinel'
$statusPath = Join-Path $dataDir 'status.json'
$configPath = Join-Path $dataDir 'config.json'
$ctl = Join-Path $PSScriptRoot 'sentinelctl.py'
$agentExes = @('claude.exe', 'cursor.exe', 'codex.exe', 'chatgpt.exe')

function Get-AgentIdentity {
    try {
        $cur = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
        for ($i = 0; $i -lt 32; $i++) {
            if ($null -eq $cur) { break }
            $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($cur.ParentProcessId)"
            if ($null -eq $parent) { break }
            if ($agentExes -contains $parent.Name.ToLower()) {
                $proc = Get-Process -Id $parent.ProcessId
                $epoch = [datetime]'1970-01-01T00:00:00Z'
                return @([int]$parent.ProcessId, [double]($proc.StartTime.ToUniversalTime() - $epoch).TotalSeconds)
            }
            $cur = $parent
        }
    } catch { }
    $self = Get-Process -Id $PID
    $epoch = [datetime]'1970-01-01T00:00:00Z'
    return @([int]$PID, [double]($self.StartTime.ToUniversalTime() - $epoch).TotalSeconds)
}

if (-not $Repo) { $Repo = Split-Path -Leaf (Get-Location).Path }
$identity = Get-AgentIdentity
$ownerPid = [int]$identity[0]
$ownerStarted = [double]$identity[1]
$toolUseId = [guid]::NewGuid().ToString('N')

if ($ResourceClass -eq 'AUTO') {
    $ResourceClass = (& py -c "import sys;sys.path.insert(0,r'$((Split-Path $PSScriptRoot -Parent))');from sentinel.coordinator import classify_command;print(classify_command(sys.argv[1]))" $Command).Trim()
}
if ($ResourceClass -eq 'LIGHT') {
    & cmd.exe /d /s /c $Command
    exit $LASTEXITCODE
}

$request = @{
    owner_pid = $ownerPid
    owner_started = $ownerStarted
    repo = $Repo
    command = $Command
    resource_class = $ResourceClass
    priority = $Priority
    tool_use_id = $toolUseId
} | ConvertTo-Json -Compress
$requestB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($request))

& py $ctl --data-dir $dataDir wait --request-b64 $requestB64 --status-file $statusPath --config-file $configPath --timeout-sec $TimeoutSec
if ($LASTEXITCODE -ne 0) { throw "Resource Sentinel reservation timed out or was denied." }

$outcome = 'failed'
$exitCode = 1
try {
    & cmd.exe /d /s /c $Command
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) { $outcome = 'success' }
} finally {
    & py $ctl --data-dir $dataDir release --owner-pid $ownerPid --tool-use-id $toolUseId --outcome $outcome | Out-Null
}
exit $exitCode
