$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/legacy-mutation.ps1')

function Assert-Legacy($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function New-FixtureProcess([int]$ProcessId = 101, [long]$Birth = 134342315823996135) {
    return [pscustomobject]@{ Id = $ProcessId; StartTime = [datetime]::FromFileTimeUtc($Birth) }
}
function New-FixtureAckRow($Candidate, [hashtable]$Changes = @{}) {
    $row = [ordered]@{ pid = $Candidate.pid; created_filetime_100ns = $Candidate.created_filetime_100ns;
        status = 'applied'; reason = 'ok'; priority_before = $null; priority_after = $null;
        io_applied = $null; trim_applied = $false }
    foreach ($name in $Changes.Keys) { $row[$name] = $Changes[$name] }
    return [pscustomobject]$row
}
function New-FixtureAck([object[]]$Rows = @(), [bool]$Available = $true) {
    return [pscustomobject]@{ protocol_version = 1; available = $Available; reason = 'fixture_result'; results = @($Rows) }
}

$fixtureDir = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-legacy-adapter-test-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($fixtureDir)
# Dot-source first, then preserve and replace the real execution entry points.
# Every Invoke in this test remains inside these mocks; no Python or OS setter runs.
$savedBoundedQuery = (Get-Item Function:\Invoke-BoundedQuery).ScriptBlock
$savedGetCommandItem = Get-Item Function:\Get-Command -ErrorAction SilentlyContinue
$savedGetCommand = if ($null -ne $savedGetCommandItem) { $savedGetCommandItem.ScriptBlock } else { $null }
$savedCulture = [Threading.Thread]::CurrentThread.CurrentCulture
$script:legacyFixtureCalls = 0
$script:legacyFixtureThrow = $false
$script:legacyFixtureRaw = ''
$script:legacyFixtureRequest = $null
$script:legacyFixtureInput = $null
$script:legacyFixtureArgs = $null

function Get-Command {
    [CmdletBinding()]
    param([string]$Name)
    if ($Name -ne 'python.exe') { throw 'UnexpectedFixtureCommandLookup' }
    return [pscustomobject]@{ Source = 'fixture-python-never-executed.exe' }
}
function Invoke-BoundedQuery([string]$FileName, [string]$Arguments, [int]$TimeoutMs = 3000) {
    $script:legacyFixtureCalls++
    Assert-Legacy ($FileName -eq 'fixture-python-never-executed.exe') 'Adapter must use the mocked interpreter'
    Assert-Legacy ($TimeoutMs -gt 0 -and $TimeoutMs -le 3000) 'Worker wait must stay bounded'
    $inputs = @(Get-ChildItem -LiteralPath $fixtureDir -Filter 'legacy-mutation-*.json' -File)
    Assert-Legacy ($inputs.Count -eq 1) 'Exactly one isolated request file must exist during dispatch'
    $script:legacyFixtureInput = $inputs[0].FullName
    $script:legacyFixtureArgs = $Arguments
    $script:legacyFixtureRequest = Get-Content -LiteralPath $script:legacyFixtureInput -Raw | ConvertFrom-Json
    if ($script:legacyFixtureThrow) { throw 'OptionalProbeTimeout private-fixture-secret' }
    return $script:legacyFixtureRaw
}
function Assert-RejectedFixtureAck($BadAck, [hashtable]$Requested, [string]$Label) {
    $script:legacyFixtureRaw = $BadAck | ConvertTo-Json -Depth 8 -Compress
    $before = $script:legacyFixtureCalls
    $actual = @(Invoke-SentinelLegacyMutation -DataDir $fixtureDir -Candidates @($Requested.Values) *>&1)
    Assert-Legacy ($actual.Count -eq 1 -and $actual[0].available -eq $false) "Invalid ACK must be unavailable: $Label"
    Assert-Legacy ($script:legacyFixtureCalls -eq $before + 1) "Invalid ACK must not cause retry: $Label"
    Assert-Legacy (-not (Test-Path -LiteralPath $script:legacyFixtureInput)) "Request file must be cleaned: $Label"
    Assert-Legacy (($actual | ConvertTo-Json -Depth 8 -Compress) -notmatch 'private-fixture-secret') 'Raw failure data must not escape'
}
function Assert-RejectedFixtureCandidates([object[]]$BadCandidates, [string]$Label) {
    $before = $script:legacyFixtureCalls
    $actual = @(Invoke-SentinelLegacyMutation -DataDir $fixtureDir -Candidates $BadCandidates *>&1)
    Assert-Legacy ($actual.Count -eq 1 -and $actual[0].available -eq $false) "Invalid candidates must be unavailable: $Label"
    Assert-Legacy ($script:legacyFixtureCalls -eq $before) "Invalid candidates must not dispatch: $Label"
    Assert-Legacy (@(Get-ChildItem -LiteralPath $fixtureDir -Filter 'legacy-mutation-*.json' -File).Count -eq 0) "Invalid input must not leave request files: $Label"
}

try {
    $candidates = @{}
    $process = New-FixtureProcess
    [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('fr-FR')
    Assert-Legacy (Add-SentinelLegacyCandidate -Candidates $candidates -Process $process -PriorityAction demote) 'Candidate must be accepted'
    Assert-Legacy ($candidates['101'].created_filetime_100ns -is [string] -and
        $candidates['101'].created_filetime_100ns -ceq '134342315823996135') 'FILETIME must remain exact invariant decimal above 2^53'
    [Threading.Thread]::CurrentThread.CurrentCulture = $savedCulture
    Assert-Legacy (Add-SentinelLegacyCandidate -Candidates $candidates -Process $process -IoPriority 1 -Trim $true) 'Same identity must merge'
    Assert-Legacy ($candidates.Count -eq 1 -and $candidates['101'].priority_action -eq 'demote' -and
        $candidates['101'].io_priority -eq 1 -and $candidates['101'].trim) 'Merge must retain priority and add independent actions'
    $beforeCandidate = $candidates['101'] | ConvertTo-Json -Compress
    Assert-Legacy (-not (Add-SentinelLegacyCandidate -Candidates $candidates -Process (New-FixtureProcess 101 134342315823996136) -PriorityAction restore)) 'Reused PID must not merge'
    Assert-Legacy (($candidates['101'] | ConvertTo-Json -Compress) -ceq $beforeCandidate) 'Rejected PID reuse must preserve original candidate'
    Assert-Legacy (-not (Add-SentinelLegacyCandidate -Candidates $candidates -Process (New-FixtureProcess 0))) 'Invalid PID must be rejected'
    Assert-Legacy (-not (Add-SentinelLegacyCandidate -Candidates $candidates -Process (New-FixtureProcess 102) -IoPriority 3)) 'Invalid I/O level must be rejected'
    $full = @{}
    for ($index = 0; $index -lt 256; $index++) {
        Assert-Legacy (Add-SentinelLegacyCandidate -Candidates $full -Process (New-FixtureProcess (1000 + $index))) 'First 256 candidates must fit'
    }
    Assert-Legacy (-not (Add-SentinelLegacyCandidate -Candidates $full -Process (New-FixtureProcess 2000))) '257th identity must be rejected'
    Assert-Legacy (Add-SentinelLegacyCandidate -Candidates $full -Process (New-FixtureProcess 1000) -Trim $true) 'An existing identity may merge at capacity'
    Assert-Legacy ($full.Count -eq 256) 'Capacity rejection must not grow the batch'

    $confirmed = New-FixtureAckRow $candidates['101'] @{ priority_before = 'AboveNormal'; priority_after = 'BelowNormal'; io_applied = 1; trim_applied = $true }
    $script:legacyFixtureRaw = New-FixtureAck @($confirmed) | ConvertTo-Json -Depth 8 -Compress
    $response = Invoke-SentinelLegacyMutation -DataDir $fixtureDir -Candidates @($candidates.Values)
    Assert-Legacy ($response.available -and $script:legacyFixtureCalls -eq 1) 'A valid ACK must survive exactly one dispatch'
    Assert-Legacy ($script:legacyFixtureRequest.protocol_version -eq 1 -and @($script:legacyFixtureRequest.candidates).Count -eq 1) 'Worker input must contain protocol and bounded candidates'
    Assert-Legacy ($script:legacyFixtureRequest.candidates[0].created_filetime_100ns -is [string] -and
        $script:legacyFixtureRequest.candidates[0].created_filetime_100ns -ceq '134342315823996135') 'JSON must not round FILETIME'
    Assert-Legacy ($script:legacyFixtureArgs.Contains('--data-dir "' + $fixtureDir + '"') -and
        $script:legacyFixtureArgs.Contains('--input "' + $script:legacyFixtureInput + '"')) 'Arguments must refer to quoted isolated paths'
    Assert-Legacy (-not (Test-Path -LiteralPath $script:legacyFixtureInput)) 'Successful dispatch must remove only its request file'
    $callsBeforeEmpty = $script:legacyFixtureCalls
    $empty = Invoke-SentinelLegacyMutation -DataDir $fixtureDir -Candidates @()
    Assert-Legacy ($empty.available -and @($empty.results).Count -eq 0 -and $script:legacyFixtureCalls -eq $callsBeforeEmpty) 'Empty batch must not launch a worker'

    $badRows = @(
        @{ label = 'wrong birth'; changes = @{ created_filetime_100ns = '134342315823996136' } },
        @{ label = 'numeric birth'; changes = @{ created_filetime_100ns = [long]134342315823996135 } },
        @{ label = 'unrequested PID'; changes = @{ pid = 999 } },
        @{ label = 'string PID'; changes = @{ pid = '101' } },
        @{ label = 'unknown status'; changes = @{ status = 'success' } },
        @{ label = 'bad trim type'; changes = @{ trim_applied = 1 } },
        @{ label = 'wrong I/O action'; changes = @{ io_applied = 2 } },
        @{ label = 'unknown priority'; changes = @{ priority_before = 'SUPER' } },
        @{ label = 'raw reason'; changes = @{ reason = 'private-fixture-secret' } },
        @{ label = 'skipped mutation'; changes = @{ status = 'skipped'; trim_applied = $true } }
    )
    foreach ($case in $badRows) {
        Assert-RejectedFixtureAck (New-FixtureAck @((New-FixtureAckRow $candidates['101'] $case.changes))) $candidates $case.label
    }
    Assert-RejectedFixtureAck (New-FixtureAck @($confirmed, $confirmed)) $candidates 'duplicate identity'
    Assert-RejectedFixtureAck ([pscustomobject]@{ protocol_version = 2; available = $true; reason = 'ok'; results = @() }) $candidates 'wrong protocol'
    Assert-RejectedFixtureAck ([pscustomobject]@{ protocol_version = '1'; available = $true; reason = 'ok'; results = @() }) $candidates 'string protocol'
    Assert-RejectedFixtureAck ([pscustomobject]@{ protocol_version = 1; available = 'true'; reason = 'ok'; results = @() }) $candidates 'string availability'
    Assert-RejectedFixtureAck ([pscustomobject]@{ protocol_version = 1; available = $true; reason = 'ok'; results = $confirmed }) $candidates 'results object'
    $missingRow = New-FixtureAckRow $candidates['101']
    $missingRow.PSObject.Properties.Remove('priority_before')
    Assert-RejectedFixtureAck (New-FixtureAck @($missingRow)) $candidates 'missing row field'
    $extraRow = New-FixtureAckRow $candidates['101']
    $extraRow | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    Assert-RejectedFixtureAck (New-FixtureAck @($extraRow)) $candidates 'extra row field'
    Assert-RejectedFixtureAck ([pscustomobject]@{ protocol_version = 1; available = $true; results = @() }) $candidates 'missing envelope field'
    Assert-RejectedFixtureAck ([pscustomobject]@{ protocol_version = 1; available = $true; reason = 'ok'; results = @(); unexpected = $true }) $candidates 'extra envelope field'
    $missingCandidate = @{}
    foreach ($name in $candidates['101'].Keys) { $missingCandidate[$name] = $candidates['101'][$name] }
    $missingCandidate.Remove('restore_priority')
    Assert-RejectedFixtureCandidates @($missingCandidate) 'missing candidate field'
    $extraCandidate = @{}
    foreach ($name in $candidates['101'].Keys) { $extraCandidate[$name] = $candidates['101'][$name] }
    $extraCandidate['unexpected'] = $true
    Assert-RejectedFixtureCandidates @($extraCandidate) 'extra candidate field'
    Assert-RejectedFixtureCandidates @($candidates['101'], $candidates['101']) 'duplicate candidate identity'
    $none = @{}
    $null = Add-SentinelLegacyCandidate -Candidates $none -Process (New-FixtureProcess 102)
    Assert-RejectedFixtureAck (New-FixtureAck @((New-FixtureAckRow $none['102'] @{ priority_before = 'Normal'; priority_after = 'BelowNormal' }))) $none 'unrequested priority'
    Assert-RejectedFixtureAck (New-FixtureAck @((New-FixtureAckRow $none['102'] @{ io_applied = 1 }))) $none 'unrequested I/O'
    Assert-RejectedFixtureAck (New-FixtureAck @((New-FixtureAckRow $none['102'] @{ trim_applied = $true }))) $none 'unrequested trim'
    $script:legacyFixtureRaw = '{private-fixture-secret'
    $beforeMalformed = $script:legacyFixtureCalls
    $malformed = @(Invoke-SentinelLegacyMutation -DataDir $fixtureDir -Candidates @($candidates.Values) *>&1)
    Assert-Legacy ($malformed.Count -eq 1 -and -not $malformed[0].available -and
        $script:legacyFixtureCalls -eq $beforeMalformed + 1) 'Malformed JSON must reject without retry'
    Assert-Legacy (($malformed | ConvertTo-Json -Depth 8 -Compress) -notmatch 'private-fixture-secret') 'Malformed JSON must not disclose worker output'
    Assert-Legacy (-not (Test-Path -LiteralPath $script:legacyFixtureInput)) 'Malformed JSON must clean its request file'
    $script:legacyFixtureThrow = $true
    $beforeTimeout = $script:legacyFixtureCalls
    $timedOut = @(Invoke-SentinelLegacyMutation -DataDir $fixtureDir -Candidates @($candidates.Values) *>&1)
    Assert-Legacy ($timedOut.Count -eq 1 -and -not $timedOut[0].available) 'Timeout must return one unavailable result'
    Assert-Legacy ($script:legacyFixtureCalls -eq $beforeTimeout + 1) 'Timeout must not retry or invoke fallback'
    Assert-Legacy (($timedOut | ConvertTo-Json -Depth 8 -Compress) -notmatch 'private-fixture-secret') 'Timeout exception content must stay private'
    Assert-Legacy (-not (Test-Path -LiteralPath $script:legacyFixtureInput)) 'Timeout must remove its request file'
    $script:legacyFixtureThrow = $false

    $demoted = @{}
    $trims = @{}
    $targets = @{ '101' = 8MB }
    $stats = Update-SentinelLegacyMutationRecords -Response $response -Candidates $candidates -Demoted $demoted -Trims $trims -TrimTargets $targets -NowEpoch 200
    Assert-Legacy ($demoted['101'] -ceq 'AboveNormal' -and $trims['101'] -eq 200) 'Confirmed priority and trim must update records'
    Assert-Legacy ($stats.trim_count -eq 1 -and $stats.trim_target_mb -eq 8) 'Trim totals must use the matching requested target'
    $partialRow = New-FixtureAckRow $candidates['101'] @{ status = 'partial'; reason = 'legacy_mutation_unverified'; priority_before = 'Normal'; priority_after = 'BelowNormal'; trim_applied = $true }
    $partialDemoted = @{}
    $partialTrims = @{}
    $partialStats = Update-SentinelLegacyMutationRecords (New-FixtureAck @($partialRow)) $candidates $partialDemoted $partialTrims $targets 201
    Assert-Legacy ($partialDemoted['101'] -ceq 'Normal' -and $partialTrims['101'] -eq 201 -and $partialStats.trim_count -eq 1) 'Partial failure must preserve separately confirmed priority and trim acknowledgements'

    foreach ($beforePriority in @('Normal', 'AboveNormal', 'High', 'Idle', 'BelowNormal', 'RealTime')) {
        $record = @{}
        $row = New-FixtureAckRow $candidates['101'] @{ priority_before = $beforePriority; priority_after = 'BelowNormal' }
        $null = Update-SentinelLegacyMutationRecords (New-FixtureAck @($row)) $candidates $record @{} @{} 202
        Assert-Legacy ($record.ContainsKey('101') -eq ($beforePriority -cin @('Normal', 'AboveNormal', 'High'))) 'Only confirmed eligible demotions may create a record'
    }
    $unverified = New-FixtureAckRow $candidates['101'] @{ status = 'partial'; priority_before = 'Normal' }
    $noReadback = @{}
    $null = Update-SentinelLegacyMutationRecords (New-FixtureAck @($unverified)) $candidates $noReadback @{} @{} 202
    Assert-Legacy ($noReadback.Count -eq 0) 'Priority Set without confirmed readback must not create a record'

    $restores = @{}
    $null = Add-SentinelLegacyCandidate -Candidates $restores -Process $process -PriorityAction restore -RestorePriority AboveNormal -IoPriority 2
    foreach ($case in @(
        @{ before = 'BelowNormal'; after = 'AboveNormal'; status = 'applied'; clears = $true },
        @{ before = 'Idle'; after = 'Idle'; status = 'applied'; clears = $true },
        @{ before = 'BelowNormal'; after = $null; status = 'partial'; clears = $false },
        @{ before = 'BelowNormal'; after = 'Normal'; status = 'partial'; clears = $false },
        @{ before = 'Idle'; after = 'Idle'; status = 'skipped'; clears = $false }
    )) {
        $record = @{ '101' = 'AboveNormal' }
        $row = New-FixtureAckRow $restores['101'] @{ priority_before = $case.before; priority_after = $case.after; status = $case.status }
        $null = Update-SentinelLegacyMutationRecords (New-FixtureAck @($row)) $restores $record @{} @{} 203
        Assert-Legacy ($record.ContainsKey('101') -eq (-not $case.clears)) 'Restore cleanup requires observed target or verified unchanged non-BelowNormal priority'
    }
    $frozenDemoted = @{ '101' = 'High'; '999' = 'Normal' }
    $frozenTrims = @{ '101' = 5; '999' = 7 }
    $frozenTargets = @{ '101' = 8MB; '999' = 2MB }
    foreach ($badResponse in @(
        (New-FixtureAck @($confirmed) $false),
        (New-FixtureAck @((New-FixtureAckRow $candidates['101'] @{ status = 'skipped' }))),
        (New-FixtureAck @((New-FixtureAckRow $candidates['101'] @{ created_filetime_100ns = '134342315823996136'; trim_applied = $true }))),
        (New-FixtureAck @($confirmed, (New-FixtureAckRow $candidates['101'] @{ pid = 999; trim_applied = $true })))
    )) {
        $stats = Update-SentinelLegacyMutationRecords $badResponse $candidates $frozenDemoted $frozenTrims $frozenTargets 999
        Assert-Legacy ($frozenDemoted.Count -eq 2 -and $frozenDemoted['101'] -ceq 'High' -and $frozenDemoted['999'] -ceq 'Normal') 'Unavailable, skipped, or malformed response must preserve demotion records'
        Assert-Legacy ($frozenTrims.Count -eq 2 -and $frozenTrims['101'] -eq 5 -and $frozenTrims['999'] -eq 7) 'Invalid later ACK must prevent even earlier trim bookkeeping'
        Assert-Legacy ($frozenTargets['101'] -eq 8MB -and $frozenTargets['999'] -eq 2MB -and $stats.trim_count -eq 0 -and $stats.trim_target_mb -eq 0) 'Rejected response must preserve targets and report no confirmed trims'
    }
    Write-Output 'Legacy mutation adapter: exact candidates, bounded mock dispatch, ACK rejection and conservative bookkeeping passed.'
} finally {
    [Threading.Thread]::CurrentThread.CurrentCulture = $savedCulture
    Set-Item -Path Function:\Invoke-BoundedQuery -Value $savedBoundedQuery
    if ($null -ne $savedGetCommand) {
        Set-Item -Path Function:\Get-Command -Value $savedGetCommand
    } else {
        Remove-Item -LiteralPath Function:\Get-Command
    }
    $resolvedFixture = [IO.Path]::GetFullPath($fixtureDir)
    $resolvedTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolvedFixture.StartsWith($resolvedTempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path $resolvedFixture -Leaf) -notlike 'sentinel-legacy-adapter-test-*') { throw 'UnsafeFixtureCleanupPath' }
    Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
}
