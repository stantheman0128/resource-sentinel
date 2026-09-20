# Intents and acknowledged bookkeeping only. The Python executor owns POLICY
# through native validation and writes; this adapter never receives permission
# to perform a later PowerShell setter and has no native fallback.
. (Join-Path $PSScriptRoot 'bounded-query.ps1')

function Test-SentinelLegacyInteger($Value) {
    return ($Value -is [int] -or $Value -is [long])
}

function Test-SentinelLegacyBirth($Value) {
    if ($Value -isnot [string] -or $Value -notmatch '^[1-9][0-9]{0,19}$') { return $false }
    $parsed = [uint64]0
    return [uint64]::TryParse($Value, [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)
}

function Test-SentinelLegacyPriority($Value) {
    return ($Value -is [string] -and $Value -cin @('Idle', 'BelowNormal', 'Normal', 'AboveNormal', 'High', 'RealTime'))
}

function Test-SentinelLegacyFields($Value, [string[]]$Names) {
    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties.Name)
    if ($Value -is [System.Collections.IDictionary]) { $actual = @($Value.Keys) }
    if ($actual.Count -ne $Names.Count) { return $false }
    foreach ($name in $Names) { if ($actual -cnotcontains $name) { return $false } }
    return $true
}

function Add-SentinelLegacyCandidate {
    param([hashtable]$Candidates, $Process,
          [ValidateSet('none', 'demote', 'restore')][string]$PriorityAction = 'none',
          [string]$RestorePriority = 'Normal', $IoPriority = $null, [bool]$Trim = $false)
    try {
        $processId = [int]$Process.Id
        $birth = $Process.StartTime.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
        if ($processId -le 0 -or -not (Test-SentinelLegacyBirth $birth) -or
            -not (Test-SentinelLegacyPriority $RestorePriority) -or
            ($null -ne $IoPriority -and (-not (Test-SentinelLegacyInteger $IoPriority) -or $IoPriority -notin @(1, 2)))) {
            return $false
        }
        $key = [string]$processId
        if ($Candidates.ContainsKey($key)) {
            $candidate = $Candidates[$key]
            if ($candidate.created_filetime_100ns -cne $birth) { return $false }
        } else {
            if ($Candidates.Count -ge 256) { return $false }
            $candidate = [ordered]@{ pid = $processId; created_filetime_100ns = $birth;
                priority_action = 'none'; restore_priority = 'Normal'; io_priority = $null; trim = $false }
            $Candidates[$key] = $candidate
        }
        if ($PriorityAction -ne 'none') {
            $candidate.priority_action = $PriorityAction
            $candidate.restore_priority = $RestorePriority
        }
        if ($null -ne $IoPriority) { $candidate.io_priority = [int]$IoPriority }
        if ($Trim) { $candidate.trim = $true }
        return $true
    } catch { return $false }
}

function New-SentinelLegacyUnavailable([string]$Reason) {
    return [pscustomobject]@{ protocol_version = 1; available = $false; reason = $Reason; results = @() }
}

function ConvertTo-SentinelLegacyArgument([string]$Value) {
    if ($Value.IndexOf([char]0) -ge 0) { throw 'InvalidNativeArgument' }
    # ProcessStartInfo uses Windows command-line quoting, without a shell.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Test-SentinelLegacyResponse($Response, [hashtable]$Candidates) {
    if (-not (Test-SentinelLegacyFields $Response @('protocol_version', 'available', 'reason', 'results')) -or
        -not (Test-SentinelLegacyInteger $Response.protocol_version) -or
        $Response.protocol_version -ne 1 -or $Response.available -isnot [bool] -or
        $Response.reason -isnot [string] -or $Response.reason -cnotmatch '^[a-z][a-z0-9_]{0,127}$' -or
        $null -eq $Response.results -or $Response.results -isnot [array]) { return $false }
    $seen = @{}
    foreach ($row in $Response.results) {
        if (-not (Test-SentinelLegacyFields $row @('pid', 'created_filetime_100ns', 'status', 'reason',
                'priority_before', 'priority_after', 'io_applied', 'trim_applied')) -or
            -not (Test-SentinelLegacyInteger $row.pid) -or $row.pid -le 0 -or
            -not (Test-SentinelLegacyBirth $row.created_filetime_100ns) -or
            $row.status -cnotin @('applied', 'skipped', 'partial') -or
            $row.reason -isnot [string] -or $row.reason -cnotmatch '^[a-z][a-z0-9_]{0,127}$' -or
            $row.trim_applied -isnot [bool]) { return $false }
        $key = [string]$row.pid
        if (-not $Candidates.ContainsKey($key) -or $seen.ContainsKey($key)) { return $false }
        $candidate = $Candidates[$key]
        if ($row.created_filetime_100ns -cne $candidate.created_filetime_100ns) { return $false }
        foreach ($name in @('priority_before', 'priority_after')) {
            if ($null -ne $row.$name -and -not (Test-SentinelLegacyPriority $row.$name)) { return $false }
        }
        if ($candidate.priority_action -eq 'none' -and
            ($null -ne $row.priority_before -or $null -ne $row.priority_after)) { return $false }
        if ($null -ne $row.io_applied -and
            (-not (Test-SentinelLegacyInteger $row.io_applied) -or
             $row.io_applied -notin @(1, 2) -or $row.io_applied -ne $candidate.io_priority)) { return $false }
        if ($row.trim_applied -and -not $candidate.trim) { return $false }
        if ($row.status -eq 'skipped' -and ($null -ne $row.io_applied -or $row.trim_applied)) { return $false }
        $seen[$key] = $true
    }
    # A missing acknowledgement does not release or restore anything. A global
    # unavailable result may describe partial work, but none is accepted below.
    return $true
}

function Invoke-SentinelLegacyMutation {
    param([string]$DataDir, [object[]]$Candidates)
    $inputPath = $null
    $response = New-SentinelLegacyUnavailable 'legacy_mutation_unavailable'
    $cleanupFailed = $false
    try {
        if ($Candidates.Count -gt 256) { throw 'InvalidCandidateCount' }
        $byIdentity = @{}
        foreach ($candidate in $Candidates) {
            if (-not (Test-SentinelLegacyFields $candidate @('pid', 'created_filetime_100ns', 'priority_action',
                    'restore_priority', 'io_priority', 'trim')) -or
                -not (Test-SentinelLegacyInteger $candidate.pid) -or $candidate.pid -le 0 -or
                -not (Test-SentinelLegacyBirth $candidate.created_filetime_100ns) -or
                $candidate.priority_action -cnotin @('none', 'demote', 'restore') -or
                -not (Test-SentinelLegacyPriority $candidate.restore_priority) -or $candidate.trim -isnot [bool] -or
                ($null -ne $candidate.io_priority -and (-not (Test-SentinelLegacyInteger $candidate.io_priority) -or
                 $candidate.io_priority -notin @(1, 2))) -or $byIdentity.ContainsKey([string]$candidate.pid)) {
                throw 'InvalidCandidate'
            }
            $byIdentity[[string]$candidate.pid] = $candidate
        }
        if ($Candidates.Count -eq 0) {
            return [pscustomobject]@{ protocol_version = 1; available = $true; reason = 'no_candidates'; results = @() }
        }
        $directory = [IO.Path]::GetFullPath($DataDir)
        if (-not [IO.Directory]::Exists($directory)) { throw 'DataDirectoryUnavailable' }
        $payload = @{ protocol_version = 1; candidates = @($Candidates) } | ConvertTo-Json -Depth 5 -Compress
        $utf8 = New-Object Text.UTF8Encoding($false)
        $bytes = $utf8.GetBytes($payload)
        if ($bytes.Length -gt 262144) { throw 'RequestTooLarge' }
        $inputPath = Join-Path $directory ('legacy-mutation-' + [guid]::NewGuid().ToString('N') + '.json')
        $stream = [IO.File]::Open($inputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
        $python = (Get-Command python.exe -ErrorAction Stop).Source
        $scriptFile = Join-Path $PSScriptRoot 'legacy-mutation.py'
        $arguments = (ConvertTo-SentinelLegacyArgument $scriptFile) + ' --data-dir ' +
            (ConvertTo-SentinelLegacyArgument $directory) + ' --input ' + (ConvertTo-SentinelLegacyArgument $inputPath)
        $raw = Invoke-BoundedQuery $python $arguments 3000
        if ($raw -isnot [string] -or $utf8.GetByteCount($raw) -gt 262144) { throw 'ResponseTooLarge' }
        $decoded = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not (Test-SentinelLegacyResponse $decoded $byIdentity)) { throw 'InvalidMutationAcknowledgement' }
        $response = $decoded
    } catch {
        # A timeout can follow real writes; preserve uncertainty, do not retry,
        # and do not expose raw process output or exception payloads.
        $response = New-SentinelLegacyUnavailable 'legacy_mutation_unavailable'
    } finally {
        if ($null -ne $inputPath) {
            try { [IO.File]::Delete($inputPath) } catch { $cleanupFailed = $true }
        }
    }
    if ($cleanupFailed) { return (New-SentinelLegacyUnavailable 'legacy_mutation_input_cleanup_failed') }
    return $response
}

function Update-SentinelLegacyMutationRecords {
    param($Response, [hashtable]$Candidates, [hashtable]$Demoted, [hashtable]$Trims,
          [hashtable]$TrimTargets, [double]$NowEpoch)
    $stats = @{ trim_count = 0; trim_target_mb = 0 }
    if (-not (Test-SentinelLegacyResponse $Response $Candidates) -or -not $Response.available) { return $stats }
    foreach ($row in $Response.results) {
        if ($row.status -eq 'skipped') { continue }
        $key = [string]$row.pid
        $candidate = $Candidates[$key]
        if ($candidate.priority_action -eq 'demote' -and
            $row.priority_before -cin @('Normal', 'AboveNormal', 'High') -and
            $row.priority_after -ceq 'BelowNormal' -and -not $Demoted.ContainsKey($key)) {
            $Demoted[$key] = $row.priority_before
        } elseif ($candidate.priority_action -eq 'restore' -and $null -ne $row.priority_before -and
                  $null -ne $row.priority_after -and
                  ($row.priority_after -ceq $candidate.restore_priority -or
                   ($row.priority_before -cne 'BelowNormal' -and $row.priority_after -ceq $row.priority_before))) {
            $Demoted.Remove($key)
        }
        if ($row.trim_applied) {
            $Trims[$key] = $NowEpoch
            $stats.trim_count++
            if ($TrimTargets.ContainsKey($key)) {
                $stats.trim_target_mb += [math]::Round([long]$TrimTargets[$key] / 1MB, 0)
            }
        }
    }
    return $stats
}
