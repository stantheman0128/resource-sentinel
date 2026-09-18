# Explicit isolated Scheduled Task experiment. No Job/CPU control.
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$nonce = [guid]::NewGuid().ToString('N')
$taskName = 'ResourceSentinelAdaptiveTest-' + $nonce
$taskPath = '\'
$description = 'Isolated read-only adaptive host probe ' + $nonce
$taskCreated = $false
$registrationAttempted = $false
$reportPath = $null
$taskExecutable = $taskArguments = $principalSid = $null
$report = [ordered]@{ schema_version=1; started_at=(Get-Date -Format o); task_name=$taskName; task_path=$taskPath
    result='not_started'; task_created=$false; task_registration_attempted=$false; task_removed=$false; cleanup_state='not_created'
    job_control_writes=0; production_tasks_changed=0 }

function Get-ExactProbeTask {
    # Task names are not unique across task folders. This scoped enumeration
    # distinguishes an absent task from a failed or denied query.
    $probeTaskMatches = @(Get-ScheduledTask -TaskPath $taskPath -ErrorAction Stop | Where-Object { $_.TaskName -ceq $taskName })
    if ($probeTaskMatches.Count -gt 1) { throw 'AmbiguousProbeTask' }
    if ($probeTaskMatches.Count -eq 1) { return $probeTaskMatches[0] }
    return $null
}

function Assert-OwnedProbeTask($Task) {
    if (-not $Task) { throw 'ProbeTaskMissing' }
    $registeredUser = [string]$Task.Principal.UserId
    $registeredSid = if ($registeredUser -match '^S-1-') {
        [Security.Principal.SecurityIdentifier]::new($registeredUser).Value
    } else {
        [Security.Principal.NTAccount]::new($registeredUser).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if (-not $Task -or $Task.TaskPath -cne $taskPath -or $Task.TaskName -cne $taskName -or
        $Task.Description -cne $description -or @($Task.Actions).Count -ne 1 -or
        $Task.Actions[0].Execute -ine $taskExecutable -or $Task.Actions[0].Arguments -cne $taskArguments -or
        $Task.Actions[0].WorkingDirectory -ine $repo -or $registeredSid -ine $principalSid -or
        [string]$Task.Principal.LogonType -ne 'Interactive' -or [string]$Task.Principal.RunLevel -ne 'Limited') {
        throw 'ProbeTaskOwnershipChanged'
    }
}

function Test-ValidHostObservation($Observation) {
    return ($Observation -and $Observation.schema_version -eq 1 -and $Observation.validity -eq 'valid' -and
        $Observation.in_any_job -is [bool] -and ($Observation.pid -is [int] -or $Observation.pid -is [long]) -and $Observation.pid -gt 0 -and
        [string]$Observation.creation_filetime -match '^[1-9][0-9]+$' -and
        ($Observation.session_id -is [int] -or $Observation.session_id -is [long]) -and $Observation.session_id -ge 0 -and
        [string]$Observation.authentication_luid -match '^[0-9a-f]{16}$')
}

try {
    $outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
    if (-not [IO.Directory]::Exists($outputRoot)) { throw 'OutputDirectoryMustExist' }
    $outputRoot = (Resolve-Path -LiteralPath $outputRoot).ProviderPath
    if ($outputRoot -match '(?i)(^|[\\/])\.resource-sentinel([\\/]|$)') { throw 'ProductionDataDirectoryForbidden' }
    $runDirectory = Join-Path $outputRoot $nonce
    $null = New-Item -ItemType Directory -Path $runDirectory
    $resultPath = Join-Path $runDirectory 'task-host.json'
    $callerPath = Join-Path $runDirectory 'caller-host.json'
    $reportPath = Join-Path $runDirectory 'task-probe-result.json'
    $python = (& py -c 'import sys;print(sys.executable)').Trim()
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'PythonUnavailable' }
    $probe = Join-Path $PSScriptRoot 'probe_adaptive_host.py'
    & $python $probe --output $callerPath
    $report.caller_probe_exit_code = $LASTEXITCODE
    $caller = Get-Content -LiteralPath $callerPath -Raw | ConvertFrom-Json
    $report.caller_observation = $caller
    $runner = Join-Path $runDirectory 'run-probe.ps1'
    $escapedPython = $python.Replace("'", "''")
    $escapedProbe = $probe.Replace("'", "''")
    $escapedResult = $resultPath.Replace("'", "''")
    @('$ErrorActionPreference = ''Stop''',
      "& '$escapedPython' '$escapedProbe' --output '$escapedResult'",
      'exit $LASTEXITCODE') | Set-Content -LiteralPath $runner -Encoding UTF8
    # PSHOME may belong to pwsh, which does not contain powershell.exe.
    $taskExecutable = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $taskExecutable -PathType Leaf)) { throw 'WindowsPowerShellUnavailable' }
    $taskArguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $runner
    $principalSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $action = New-ScheduledTaskAction -Execute $taskExecutable -Argument $taskArguments -WorkingDirectory $repo
    $principal = New-ScheduledTaskPrincipal -UserId $principalSid -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description $description
    # No -Force: a nonce collision must never replace an existing task.
    $registrationAttempted = $true
    $report.task_registration_attempted = $true
    $null = Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -InputObject $task
    $taskCreated = $true
    $report.task_created = $true
    Assert-OwnedProbeTask (Get-ExactProbeTask)
    Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $resultPath) -and $deadline.Elapsed.TotalSeconds -lt 30) { Start-Sleep -Milliseconds 200 }
    $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath
    $report.last_task_result = $info.LastTaskResult
    if (Test-Path -LiteralPath $resultPath) {
        $observation = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        $report.observation = $observation
        if (-not (Test-ValidHostObservation $observation) -or -not (Test-ValidHostObservation $caller)) {
            $report.result = 'host_observation_unknown'
        } elseif ($observation.python_bitness -ne 64 -or $caller.python_bitness -ne 64) {
            $report.result = 'unsupported_python_bitness'
        } elseif ($observation.authentication_luid -cne $caller.authentication_luid -or $observation.session_id -ne $caller.session_id) {
            $report.result = 'unsupported_logon_or_session_mismatch'
        } elseif ($observation.in_any_job) {
            # Presence alone identifies neither Job owner nor CPU denominator.
            $report.result = 'unsupported_parent_job_present'
        } else { $report.result = 'candidate_host_not_control_verified' }
    } else { $report.result = 'no_child_evidence' }
} catch {
    $report.result = 'blocked'
    $report.error_type = $_.Exception.GetType().FullName
    $report.error_id = $_.FullyQualifiedErrorId
    $report.error_hresult = $_.Exception.HResult
} finally {
    if ($registrationAttempted) {
        try {
            $owned = Get-ExactProbeTask
            if ($owned) {
                Assert-OwnedProbeTask $owned
                $cleanupWait = [Diagnostics.Stopwatch]::StartNew()
                while ([string]$owned.State -in @('Running', 'Queued') -and $cleanupWait.Elapsed.TotalSeconds -lt 5) {
                    Start-Sleep -Milliseconds 200
                    $owned = Get-ExactProbeTask
                    Assert-OwnedProbeTask $owned
                }
                $report.probe_task_stopped_for_cleanup = $false
                if ([string]$owned.State -in @('Running', 'Queued')) {
                    # Only this unchanged nonce/action/principal task may be
                    # stopped. It contains solely our read-only metadata probe.
                    Assert-OwnedProbeTask (Get-ExactProbeTask)
                    Stop-ScheduledTask -TaskName $taskName -TaskPath $taskPath
                    $report.probe_task_stopped_for_cleanup = $true
                    $stopWait = [Diagnostics.Stopwatch]::StartNew()
                    do {
                        Start-Sleep -Milliseconds 200
                        $owned = Get-ExactProbeTask
                        Assert-OwnedProbeTask $owned
                    } while ([string]$owned.State -in @('Running', 'Queued') -and $stopWait.Elapsed.TotalSeconds -lt 5)
                    if ([string]$owned.State -in @('Running', 'Queued')) { throw 'ProbeTaskStopUnverified' }
                }
                $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath
                $report.last_task_result = $info.LastTaskResult
                Assert-OwnedProbeTask (Get-ExactProbeTask)
                Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false
            }
            $report.task_removed = $null -eq (Get-ExactProbeTask)
            if (-not $report.task_removed) { throw 'ProbeTaskRemovalUnverified' }
            $report.cleanup_state = 'removed_verified'
        } catch {
            $report.cleanup_state = 'unverified'
            $report.cleanup_error_type = $_.Exception.GetType().FullName
            $report.cleanup_error_id = $_.FullyQualifiedErrorId
            $report.cleanup_error_hresult = $_.Exception.HResult
        }
    }
    $report.probe_result = $report.result
    if ($registrationAttempted -and -not $report.task_removed) { $report.result = 'cleanup_unverified' }
    if ($report.result -eq 'candidate_host_not_control_verified' -and
        ($report.last_task_result -ne 0 -or $report.probe_task_stopped_for_cleanup)) { $report.result = 'task_completion_unverified' }
    $report.completed_at = Get-Date -Format o
    if ($reportPath) {
        try { $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8 }
        catch {
            $report.result = 'report_write_failed'
            $report.report_error_type = $_.Exception.GetType().FullName
        }
    }
}
$report | ConvertTo-Json -Depth 8
if ($report.result -ne 'candidate_host_not_control_verified' -or -not $report.task_removed) { exit 2 }
