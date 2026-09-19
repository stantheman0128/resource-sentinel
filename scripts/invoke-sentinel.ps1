# Reserve local capacity, run one command, and always release the reservation.
param(
    [Parameter(Mandatory = $true)][string]$Command,
    [ValidateSet('AUTO', 'LIGHT', 'MEDIUM', 'HEAVY', 'EXTREME')][string]$ResourceClass = 'AUTO',
    [ValidateSet('P0', 'P1', 'P2', 'P3')][string]$Priority = 'P2',
    [int]$TimeoutSec = 1800,
    [string]$Repo = '',
    [switch]$UserAuthorizedExemption,
    [ValidateRange(1, 1440)][int]$ExemptionMinutes = 60,
    [string]$ExemptionReason = ''
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
                $epoch = [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
                return @([int]$parent.ProcessId, [double]($proc.StartTime.ToUniversalTime() - $epoch).TotalSeconds)
            }
            $cur = $parent
        }
    } catch { }
    $self = Get-Process -Id $PID
    $epoch = [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    return @([int]$PID, [double]($self.StartTime.ToUniversalTime() - $epoch).TotalSeconds)
}

if (-not $Repo) { $Repo = Split-Path -Leaf (Get-Location).Path }
$identity = Get-AgentIdentity
$ownerPid = [int]$identity[0]
$ownerStarted = [double]$identity[1]
$toolUseId = [guid]::NewGuid().ToString('N')

$exemptionId = ''
$outcome = 'failed'
$exitCode = 1
try {
    if ($UserAuthorizedExemption) {
        if (-not $ExemptionReason.Trim()) { throw 'ExemptionReason must describe the explicit user authorization.' }
        # Use this dedicated command wrapper, never a shared desktop app ancestor.
        $self = Get-Process -Id $PID
        $ownerPid = [int]$PID
        $ownerStarted = ($self.StartTime.ToUniversalTime() - [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).TotalSeconds
        $grantJson = & py $ctl --data-dir $dataDir exemption-grant --pid $PID --minutes $ExemptionMinutes --reason $ExemptionReason --user-authorized
        if ($LASTEXITCODE -ne 0) { throw 'Resource Sentinel exemption could not be registered.' }
        $grant = $grantJson | ConvertFrom-Json
        $exemptionId = [string]$grant.id
        if (-not $exemptionId) { throw 'Resource Sentinel returned no exemption ID.' }
        if ([string]$self.PriorityClass -eq 'BelowNormal') { $self.PriorityClass = 'Normal' }
        Write-Output "Resource Sentinel user exemption: $exemptionId; expires at epoch $($grant.expires_at)."
    } elseif (Test-Path (Join-Path $dataDir 'exemptions.sqlite3')) {
        # An existing grant may belong to a dedicated shell below the shared app.
        $inheritedJson = & py $ctl --data-dir $dataDir exemption-check --pid $PID
        if ($LASTEXITCODE -eq 0 -and ($inheritedJson | ConvertFrom-Json)) {
            $self = Get-Process -Id $PID
            $ownerPid = [int]$PID
            $ownerStarted = ($self.StartTime.ToUniversalTime() - [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).TotalSeconds
            if ([string]$self.PriorityClass -eq 'BelowNormal') { $self.PriorityClass = 'Normal' }
        }
    }

    if ($ResourceClass -eq 'AUTO') {
        $ResourceClass = (& py -c "import sys;sys.path.insert(0,r'$((Split-Path $PSScriptRoot -Parent))');from sentinel.coordinator import classify_command;print(classify_command(sys.argv[1], shell='cmd'))" $Command).Trim()
    }
    if ($ResourceClass -ne 'LIGHT') {
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
    }

    & cmd.exe /d /s /c $Command
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) { $outcome = 'success' }
} finally {
    try {
        & py $ctl --data-dir $dataDir release --owner-pid $ownerPid --tool-use-id $toolUseId --outcome $outcome | Out-Null
    } finally {
        if ($exemptionId) {
            & py $ctl --data-dir $dataDir exemption-revoke --id $exemptionId | Out-Null
        }
    }
}
exit $exitCode
