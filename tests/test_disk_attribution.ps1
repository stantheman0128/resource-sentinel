$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts\disk-attribution.ps1')
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Sample([string]$At, [long]$Free, $Allocation = 20GB, [string]$Probe = 'ok') {
    $start = [DateTimeOffset]$At
    [PSCustomObject]@{ observed_at = $start.ToString('o'); completed_at = $start.AddSeconds(1).ToString('o')
        disk_query_started_at = $start.AddMilliseconds(-100).ToString('o'); disk_query_completed_at = $start.ToString('o')
        pagefile_enumeration_started_at = $start.AddMilliseconds(-500).ToString('o'); pagefile_enumeration_completed_at = $start.AddMilliseconds(-200).ToString('o')
        disks = @([PSCustomObject]@{ drive = 'C:'; volume_serial = 'fixture'; free_bytes = $Free })
        pagefiles = @([PSCustomObject]@{ path = 'C:\pagefile.sys'; drive = 'C:'
            observed_at = $start.AddMilliseconds(100).ToString('o'); completed_at = $start.AddMilliseconds(200).ToString('o')
            allocation_bytes = $Allocation; allocation_source = 'FileStandardInfo'
            logical_bytes = 29GB; native_storage_bytes = $null; wmi_allocated_bytes = 20GB })
        probe_state = $Probe
        io_correlation = [PSCustomObject]@{ before_at = $start.AddMinutes(-5).ToString('o'); after_at = $start.ToString('o')
            top_writers = @(@{ name = 'fixture.exe'; mb = 266.7 }); state = 'correlation_only' } }
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-disk-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temp
try {
    $before = Sample '2026-09-19T04:09:44+08:00' 198000000000
    $after = Sample '2026-09-19T04:13:24+08:00' (198000000000 - 10246017024) 28GB
    $events = @(Compare-DiskAttribution $before $after)
    Assert ($events.Count -eq 1) 'Expected one significant volume delta'
    $event = $events[0]
    Assert ($event.interval_seconds -eq 220) 'Do not claim the configured one-minute cadence'
    Assert ($event.delta_bytes -eq -10246017024) 'Use exact free bytes, not rounded GiB'
    Assert ($event.pagefile_allocation_delta_bytes -eq 8GB) 'Native allocation uses matching endpoint pairs'
    Assert ($event.unexplained_net_allocation_bytes -eq (10246017024 - 8GB)) 'Residual subtracts only verified allocation'
    Assert (@(Compare-DiskAttribution $before $after 20 5).Count -eq 1) 'Notification threshold remains independent of event threshold'
    $after.io_correlation.top_writers[0].mb = 99999999
    $io = @(Compare-DiskAttribution $before $after)[0]
    Assert ($io.unexplained_net_allocation_bytes -eq $event.unexplained_net_allocation_bytes) 'I/O is never allocation attribution'
    $after.pagefiles[0].allocation_bytes = $null
    $missing = @(Compare-DiskAttribution $before $after)[0]
    Assert ($null -eq $missing.pagefile_allocation_delta_bytes -and $null -eq $missing.unexplained_net_allocation_bytes) 'Sharing violation must remain unknown'
    Assert ($missing.unverified_loss_bytes -eq 10246017024) 'Logical and WMI bytes cannot fill missing allocation'
    $after.pagefiles[0].allocation_bytes = 28GB
    $after.pagefiles[0].observed_at = ([DateTimeOffset]$after.observed_at).AddMinutes(-1).ToString('o')
    $mismatch = @(Compare-DiskAttribution $before $after)[0]
    Assert ($null -eq $mismatch.pagefile_allocation_delta_bytes) 'Do not subtract observations from a different time window'
    $slow = Sample '2026-09-19T04:13:24+08:00' (198000000000 - 10246017024) 28GB
    $slow.pagefile_enumeration_started_at = ([DateTimeOffset]$slow.observed_at).AddSeconds(-20).ToString('o')
    $slow.pagefile_enumeration_completed_at = ([DateTimeOffset]$slow.observed_at).AddSeconds(-19).ToString('o')
    $slow.disk_query_started_at = ([DateTimeOffset]$slow.observed_at).AddSeconds(-18).ToString('o')
    Assert ($null -eq @(Compare-DiskAttribution $before $slow)[0].pagefile_allocation_delta_bytes) 'Slow CIM reads cannot masquerade as a bounded synchronized endpoint'
    $after = Sample '2026-09-19T04:13:24+08:00' (198000000000 - 10246017024) 18GB
    $decrease = @(Compare-DiskAttribution $before $after)[0]
    Assert ($decrease.unexplained_net_allocation_bytes -eq (10246017024 + 2GB)) 'A pagefile decrease can coexist with larger unexplained allocation'
    $after.pagefiles[0].allocation_bytes = 32GB
    $offset = @(Compare-DiskAttribution $before $after)[0]
    Assert ($offset.unexplained_net_allocation_bytes -lt 0 -and $offset.unverified_loss_bytes -eq 0) 'Concurrent net frees remain a signed residual'
    $after.disks[0].volume_serial = 'replacement'
    Assert (@(Compare-DiskAttribution $before $after).Count -eq 0) 'Drive letter reuse cannot compare different volumes'
    $after = Sample '2026-09-19T04:13:24+08:00' (198000000000 - 10246017024) 28GB
    $after.pagefiles += [PSCustomObject]@{ path = 'C:\newpage.sys'; drive = 'C:'; allocation_bytes = 2GB }
    Assert ($null -eq @(Compare-DiskAttribution $before $after)[0].pagefile_allocation_delta_bytes) 'Membership changes have incomplete coverage'
    $after = Sample '2026-09-19T04:13:24+08:00' (198000000000 - 10246017024) 28GB
    $path = Join-Path $temp 'disk-attribution-state.json'
    $state = Read-DiskAttributionState $path
    $state = Update-DiskAttribution $state $before
    Assert ($state.events.Count -eq 0) 'First native sample establishes a baseline only'
    $state = Update-DiskAttribution $state $after
    Save-DiskAttributionState $path $state
    $originalBytes = [IO.File]::ReadAllText($path)
    $lock = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    $replaceFailed = $false
    try { Save-DiskAttributionState $path $state } catch { $replaceFailed = $true } finally { $lock.Dispose() }
    Assert ($replaceFailed -and [IO.File]::ReadAllText($path) -eq $originalBytes) 'Failed atomic replacement must preserve prior baseline and outbox'
    Assert (@(Get-ChildItem -LiteralPath $temp -Filter '*.tmp').Count -eq 0) 'Failed replacement must not leave temporary state files'
    foreach ($badState in @('{', '{"version":99,"events":[]}')) {
        $invalidPath = Join-Path $temp 'invalid.json'
        [IO.File]::WriteAllText($invalidPath, $badState)
        $readFailed = $false
        try { $null = Read-DiskAttributionState $invalidPath } catch { $readFailed = $true }
        Assert ($readFailed -and [IO.File]::ReadAllText($invalidPath) -eq $badState) 'Existing invalid state must not silently reset baseline or cooldown evidence'
    }
    # Simulate a collector timeout after this early disk checkpoint, before state.json.
    $state = Read-DiskAttributionState $path
    $same = Update-DiskAttribution $state $after
    Assert ($same.events.Count -eq 1) 'A replayed disk snapshot must not duplicate the event'
    $candidate = @(Get-DiskAlertCandidates $same ([DateTimeOffset]$after.observed_at))
    Assert ($candidate.Count -eq 1 -and $candidate[0].notification_state -eq 'pending') 'Only pending evidence can begin a send'
    $candidate[0].notification_state = 'attempting'
    $candidate[0].notification_attempted_at = $after.observed_at
    Save-DiskAttributionState $path $same
    $state = Update-DiskAttribution (Read-DiskAttributionState $path) $after
    Assert ($state.events[0].notification_state -eq 'unknown_delivery') 'A crashed network attempt is not confirmed sent'
    Assert (@(Get-DiskAlertCandidates $state ([DateTimeOffset]$after.observed_at)).Count -eq 0) 'Ambiguous delivery is not automatically replayed'
    $later = Sample '2026-09-19T04:14:24+08:00' (198000000000 - 20246017024) 28GB
    $state = Update-DiskAttribution $state $later
    Assert (@(Get-DiskAlertCandidates $state ([DateTimeOffset]$later.observed_at)).Count -eq 0) 'Cooldown survives interrupted collector and covers unknown delivery'
    Assert ($state.events[-1].notification_state -eq 'suppressed_cooldown') 'Suppression is explicit evidence'
    foreach ($index in 1..65) {
        $state.events += [PSCustomObject]@{ event_id = "noise-$index"; drive = 'D:'; after_at = $later.observed_at
            notification_state = 'pending'; notification_attempted_at = $null; ledger_state = 'written'; alert_eligible = $false }
    }
    $state = Update-DiskAttribution $state $later
    Assert ($state.events.Count -eq 64 -and $state.cooldowns.'C:' -eq $after.observed_at) 'Cooldown survives bounded outbox eviction'
    $newLoss = Sample '2026-09-19T04:15:24+08:00' (198000000000 - 30246017024) 28GB
    $state = Update-DiskAttribution $state $newLoss
    Assert (@(Get-DiskAlertCandidates $state ([DateTimeOffset]$newLoss.observed_at)).Count -eq 0) 'Evicting the original attempted event must not admit another alert in cooldown'
    $template = (Get-Content -LiteralPath (Join-Path $root 'scripts\messages.json') -Raw | ConvertFrom-Json).disk_shrink
    $message = Format-DiskShrinkAlert $event $template
    Assert ($message.Contains('220') -and $message.Contains($event.event_id.Substring(0, 12))) 'Notification uses actual interval and event identity'
    Assert (-not $message.Contains('{') -and -not $message.Contains('}')) 'Every template field is populated'
    # Only test-created files: native API verification never reads a production pagefile.
    $fixture = Join-Path $temp 'fixture.sys'
    [IO.File]::WriteAllBytes($fixture, (New-Object byte[] 8192))
    $native = @(Get-PagefileNativeMeasurements @([PSCustomObject]@{ Name = $fixture; AllocatedBaseSize = 2; CurrentUsage = 1 }))[0]
    Assert ($native.logical_bytes -eq 8192 -and $native.allocation_bytes -ge 8192) 'Native metadata probe failed on an ordinary isolated file'
    Assert ($native.wmi_allocated_bytes -eq 2MB -and $native.wmi_used_bytes -eq 1MB) 'WMI metadata must remain distinct from measured allocation'
    $absent = @(Get-PagefileNativeMeasurements @([PSCustomObject]@{ Name = (Join-Path $temp 'missing.sys') }))[0]
    Assert ($null -eq $absent.allocation_bytes -and $null -eq $absent.native_storage_bytes) 'Missing files must not become zero bytes'
    Write-Output 'PASS disk attribution: exact interval/bytes, native-only accounting, coverage gaps, signed residual, early checkpoint, outbox recovery, metadata probe'
} finally {
    $resolved = [IO.Path]::GetFullPath($temp)
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'sentinel-disk-test-*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
