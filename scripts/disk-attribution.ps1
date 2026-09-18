param([string]$ProbeInputPath)
# Dot-source for pure reducers. -ProbeInputPath is a bounded, read-only child probe.
# Never opens file contents, recursively scans a volume, or identifies a writer.

function Get-PagefileNativeMeasurements([object[]]$Pagefiles) {
    if (-not ('SentinelDiskNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SentinelDiskNative {
    [StructLayout(LayoutKind.Sequential)] public struct StandardInfo {
        public long AllocationSize; public long EndOfFile; public uint Links;
        public byte DeletePending; public byte Directory;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetFileInformationByHandleEx(SafeFileHandle file,
        int infoClass, out StandardInfo info, uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern uint GetCompressedFileSizeW(string name, out uint high);
    [DllImport("kernel32.dll")] public static extern void SetLastError(uint error);
}
'@
    }
    $rows = @()
    foreach ($page in @($Pagefiles | Select-Object -First 16)) {
        $name = [string]$page.Name
        if ($name -notmatch '^[A-Za-z]:\\[^\r\n]+$' -or $name.Contains('..')) { continue }
        $row = [ordered]@{ path = $name; drive = $name.Substring(0, 2).ToUpperInvariant()
            observed_at = (Get-Date).ToUniversalTime().ToString('o')
            allocation_bytes = $null; logical_bytes = $null; native_storage_bytes = $null
            allocation_source = $null; native_error = $null; storage_error = $null; logical_error = $null
            wmi_allocated_bytes = $null; wmi_used_bytes = $null }
        if ($null -ne $page.AllocatedBaseSize) { $row.wmi_allocated_bytes = [long]$page.AllocatedBaseSize * 1MB }
        if ($null -ne $page.CurrentUsage) { $row.wmi_used_bytes = [long]$page.CurrentUsage * 1MB }
        # Access 0 requests metadata only; share read/write/delete. A system file can
        # still deny access. That is unknown, not a zero-byte pagefile.
        $handle = [SentinelDiskNative]::CreateFileW($name, 0, 7, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
        try {
            if ($handle.IsInvalid) { $row.native_error = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
            else {
                $info = New-Object SentinelDiskNative+StandardInfo
                if ([SentinelDiskNative]::GetFileInformationByHandleEx($handle, 1, [ref]$info, 24)) {
                    $row.allocation_bytes = $info.AllocationSize
                    $row.logical_bytes = $info.EndOfFile
                    $row.allocation_source = 'FileStandardInfo'
                } else { $row.native_error = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
            }
        } finally { $handle.Dispose() }
        # Kept separate: for an uncompressed file this API may return logical size,
        # not cluster-rounded AllocationSize. Never silently substitute one for the other.
        [uint32]$high = 0
        [SentinelDiskNative]::SetLastError(0)
        $low = [SentinelDiskNative]::GetCompressedFileSizeW($name, [ref]$high)
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($low -eq [uint32]::MaxValue -and $errorCode -ne 0) { $row.storage_error = $errorCode }
        else { $row.native_storage_bytes = [long]([uint64]$high * 4294967296 + [uint64]$low) }
        if ($null -eq $row.logical_bytes) {
            try { $row.logical_bytes = (New-Object IO.FileInfo($name)).Length }
            catch { $row.logical_error = 'metadata_unavailable' }
        }
        $row.completed_at = (Get-Date).ToUniversalTime().ToString('o')
        $rows += [PSCustomObject]$row
    }
    return $rows
}

function Read-DiskAttributionState([string]$Path) {
    if (Test-Path -LiteralPath $Path -ErrorAction Stop) {
        if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 2MB) { throw 'OversizeDiskState' }
        $state = Get-Content -LiteralPath $Path -Raw -Encoding utf8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($state.version -eq 1 -and $null -ne $state.events) { return $state }
        throw 'UnsupportedDiskState'
    }
    return [PSCustomObject]@{ version = 1; baseline = $null; events = @(); cooldowns = @{} }
}

function Save-DiskAttributionState([string]$Path, $State) {
    $tempPath = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $json = $State | ConvertTo-Json -Depth 14 -Compress
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
        $stream = [IO.File]::Open($tempPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        # Move-Item -Force can delete the old destination before moving. File.Replace
        # provides the required single Windows replacement operation instead.
        # Windows PowerShell 5.1 binds ordinary $null to an empty string for this
        # string parameter. NullString preserves the native "no backup path" value.
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($tempPath, $Path, [NullString]::Value) }
        else { [IO.File]::Move($tempPath, $Path) }
    } finally { if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath } }
}

function Get-DiskEventId([string]$Identity) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Identity)))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function ConvertTo-DiskEventJson($Event) {
    $json = $Event | ConvertTo-Json -Depth 12 -Compress
    # Preserve events.log's existing ASCII encoding without losing Unicode names.
    return [regex]::Replace($json, '[^\x00-\x7F]', { param($match) '\u{0:x4}' -f [int][char]$match.Value })
}

function Test-DiskEndpoint($Sample) {
    try {
        if (-not $Sample.pagefile_enumeration_started_at -or -not $Sample.pagefile_enumeration_completed_at -or
            -not $Sample.disk_query_started_at -or -not $Sample.disk_query_completed_at) { return $false }
        $start = [DateTimeOffset]$Sample.pagefile_enumeration_started_at
        $enumerated = [DateTimeOffset]$Sample.pagefile_enumeration_completed_at
        $diskStart = [DateTimeOffset]$Sample.disk_query_started_at
        $diskEnd = [DateTimeOffset]$Sample.disk_query_completed_at
        $end = [DateTimeOffset]$Sample.completed_at
        if ($enumerated -lt $start -or $diskStart -lt $enumerated -or $diskEnd -lt $diskStart -or
            $diskEnd -ne [DateTimeOffset]$Sample.observed_at) { return $false }
        if (($end - $start).TotalSeconds -lt 0 -or ($end - $start).TotalSeconds -gt 5) { return $false }
        foreach ($page in @($Sample.pagefiles)) {
            if (-not $page.observed_at -or -not $page.completed_at) { return $false }
            if ([DateTimeOffset]$page.observed_at -lt $diskEnd -or [DateTimeOffset]$page.completed_at -gt $end -or
                [DateTimeOffset]$page.completed_at -lt [DateTimeOffset]$page.observed_at) { return $false }
        }
        return $true
    } catch { return $false }
}

function Compare-DiskAttribution($Before, $After, [double]$EventGiB = 2, [double]$AlertGiB = 5) {
    if ($null -eq $Before) { return @() }
    $interval = ([DateTimeOffset]$After.observed_at - [DateTimeOffset]$Before.observed_at).TotalSeconds
    if ($interval -le 0) { return @() }
    foreach ($disk in @($After.disks)) {
        if ([string]::IsNullOrWhiteSpace([string]$disk.volume_serial)) { continue }
        $old = @($Before.disks | Where-Object { $_.drive -eq $disk.drive -and $_.volume_serial -eq $disk.volume_serial })
        if ($old.Count -ne 1 -or $null -eq $disk.free_bytes -or $null -eq $old[0].free_bytes) { continue }
        [long]$delta = [long]$disk.free_bytes - [long]$old[0].free_bytes
        if ([math]::Abs($delta) -lt $EventGiB * 1GB -and -$delta -lt $AlertGiB * 1GB) { continue }
        $coverage = 'partial'; $pageDelta = $null; $pageRows = @(); [long]$measuredDelta = 0
        $beforePages = @($Before.pagefiles | Where-Object { $_.drive -eq $disk.drive })
        $afterPages = @($After.pagefiles | Where-Object { $_.drive -eq $disk.drive })
        $beforeKeys = @($beforePages | ForEach-Object { ([string]$_.path).ToLowerInvariant() } | Sort-Object -Unique)
        $afterKeys = @($afterPages | ForEach-Object { ([string]$_.path).ToLowerInvariant() } | Sort-Object -Unique)
        $complete = ($Before.probe_state -eq 'ok' -and $After.probe_state -eq 'ok' -and
            (Test-DiskEndpoint $Before) -and (Test-DiskEndpoint $After) -and
            $beforePages.Count -eq $afterPages.Count -and $beforeKeys.Count -eq $beforePages.Count -and
            $afterKeys.Count -eq $afterPages.Count -and ($beforeKeys -join '|') -eq ($afterKeys -join '|'))
        foreach ($page in $afterPages) {
            $prior = @($beforePages | Where-Object { $_.path -eq $page.path })
            $comparable = ($prior.Count -eq 1 -and @($afterPages | Where-Object { $_.path -eq $page.path }).Count -eq 1 -and $null -ne $page.allocation_bytes -and
                $null -ne $prior[0].allocation_bytes -and $page.allocation_source -eq 'FileStandardInfo' -and
                $prior[0].allocation_source -eq 'FileStandardInfo' -and
                (Test-DiskEndpoint $Before) -and (Test-DiskEndpoint $After))
            $change = $null
            if ($comparable) { $change = [long]$page.allocation_bytes - [long]$prior[0].allocation_bytes; $measuredDelta += $change }
            else { $complete = $false }
            $pageRows += [PSCustomObject]@{ path = $page.path; state = $(if ($comparable) { 'comparable' } else { 'unknown' })
                before = $(if ($prior.Count -eq 1) { $prior[0] } else { $null }); after = $page; allocation_delta_bytes = $change }
        }
        if ($complete) { $coverage = 'complete_pagefiles_only'; $pageDelta = $measuredDelta }
        # A signed residual preserves concurrent allocation/freeing. Never subtract
        # process write transfer bytes, WMI estimates, or unknown pagefile samples.
        [long]$loss = -$delta
        $residual = $null
        if ($null -ne $pageDelta) { $residual = $loss - $pageDelta }
        $id = Get-DiskEventId ($disk.drive + '|' + $disk.volume_serial + '|' + $Before.observed_at + '|' + $After.observed_at + '|' + $old[0].free_bytes + '|' + $disk.free_bytes)
        [PSCustomObject]@{ event_id = $id; type = 'disk_delta'; ts = $After.observed_at
            drive = $disk.drive; volume_serial = $disk.volume_serial
            before_at = $Before.observed_at; after_at = $After.observed_at; interval_seconds = $interval
            before_completed_at = $Before.completed_at; after_completed_at = $After.completed_at
            before_window_started_at = $Before.pagefile_enumeration_started_at
            after_window_started_at = $After.pagefile_enumeration_started_at
            before_free_bytes = [long]$old[0].free_bytes; after_free_bytes = [long]$disk.free_bytes
            delta_bytes = $delta; delta_gb = [math]::Round($delta / 1GB, 3); free_gb = [math]::Round($disk.free_bytes / 1GB, 3)
            pagefile_allocation_delta_bytes = $pageDelta; pagefile_partial_delta_bytes = $measuredDelta
            unexplained_net_allocation_bytes = $residual
            unverified_loss_bytes = $(if ($null -eq $residual) { [math]::Max([long]0, [long]$loss) } else { [math]::Max([long]0, [long]$residual) })
            coverage = $coverage; pagefiles = $pageRows; file_writer_attribution = 'unavailable'
            io_correlation = $After.io_correlation
            alert_eligible = ($loss -ge $AlertGiB * 1GB)
            notification_state = 'pending'; notification_attempted_at = $null; notification_sent_at = $null
            ledger_state = 'pending' }
    }
}

function Update-DiskAttribution($State, $Sample, [double]$EventGiB = 2, [double]$AlertGiB = 5) {
    $freshEvents = @(Compare-DiskAttribution $State.baseline $Sample $EventGiB $AlertGiB)
    $events = @($State.events)
    $cooldowns = @{}
    if ($State.cooldowns -is [System.Collections.IDictionary]) {
        foreach ($key in $State.cooldowns.Keys) { $cooldowns[$key] = $State.cooldowns[$key] }
    } elseif ($null -ne $State.cooldowns) {
        foreach ($property in $State.cooldowns.PSObject.Properties) { $cooldowns[$property.Name] = $property.Value }
    }
    foreach ($oldEvent in $events) {
        if ($oldEvent.notification_state -eq 'attempting') { $oldEvent.notification_state = 'unknown_delivery' }
        if ($oldEvent.ledger_state -eq 'attempting') { $oldEvent.ledger_state = 'unknown_write' }
        if ($oldEvent.notification_attempted_at -and (-not $cooldowns.ContainsKey($oldEvent.drive) -or
            [DateTimeOffset]$oldEvent.notification_attempted_at -gt [DateTimeOffset]$cooldowns[$oldEvent.drive])) {
            $cooldowns[$oldEvent.drive] = $oldEvent.notification_attempted_at
        }
    }
    foreach ($event in $freshEvents) {
        if (@($events | Where-Object { $_.event_id -eq $event.event_id }).Count -eq 0) { $events += $event }
    }
    # Bounded local outbox. Old retained evidence remains in events.log. Dropped
    # pending entries are explicitly counted; this is not a durable message queue.
    $dropped = [math]::Max(0, $events.Count - 64)
    return [PSCustomObject]@{ version = 1; baseline = $Sample
        events = @($events | Select-Object -Last 64); dropped_outbox_entries = $dropped; cooldowns = $cooldowns }
}

function Get-DiskAlertCandidates($State, [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow) {
    $selectedDrives = @{}
    foreach ($event in @($State.events | Sort-Object after_at -Descending)) {
        if (-not $event.alert_eligible -or $event.notification_state -ne 'pending') { continue }
        if (($Now - [DateTimeOffset]$event.after_at).TotalSeconds -gt 1800) { $event.notification_state = 'expired'; continue }
        $recent = @($State.events | Where-Object { $_.drive -eq $event.drive -and $_.notification_attempted_at -and
            ($Now - [DateTimeOffset]$_.notification_attempted_at).TotalSeconds -lt 1800 })
        $priorAttempt = $State.cooldowns.($event.drive)
        $cooling = ($priorAttempt -and ($Now - [DateTimeOffset]$priorAttempt).TotalSeconds -lt 1800)
        if ($recent.Count -gt 0 -or $cooling -or $selectedDrives.ContainsKey($event.drive)) { $event.notification_state = 'suppressed_cooldown'; continue }
        # Caller marks attempting and persists before starting a network request.
        $selectedDrives[$event.drive] = $true
        $event
    }
}

function Format-DiskShrinkAlert($Event, [string]$Template) {
    $writers = @($Event.io_correlation.top_writers | Select-Object -First 3 | ForEach-Object { "$($_.name) $($_.mb) MiB" }) -join ', '
    if (-not $writers) { $writers = 'unavailable' }
    $page = 'unknown (native allocation unavailable or endpoints incomplete)'
    if ($null -ne $Event.pagefile_allocation_delta_bytes) { $page = ('{0:N3} GiB' -f ($Event.pagefile_allocation_delta_bytes / 1GB)) }
    $unexplained = ('{0:N3} GiB' -f ($Event.unverified_loss_bytes / 1GB))
    $Template.Replace('{drive}', $Event.drive).Replace('{seconds}', ('{0:N1}' -f $Event.interval_seconds)).
        Replace('{delta}', ('{0:N3}' -f (-$Event.delta_bytes / 1GB))).Replace('{free}', ('{0:N3}' -f $Event.free_gb)).
        Replace('{writers}', $writers).Replace('{pagefile}', $page).Replace('{unexplained}', $unexplained).
        Replace('{event_id}', $Event.event_id.Substring(0, 12))
}

if ($ProbeInputPath) {
    $ErrorActionPreference = 'Stop'
    $inputData = Get-Content -LiteralPath $ProbeInputPath -Raw | ConvertFrom-Json
    $rows = @(Get-PagefileNativeMeasurements @($inputData.pagefiles))
    @{ state = $(if ($inputData.enumeration_state -eq 'ok' -and @($inputData.pagefiles).Count -le 16 -and $rows.Count -eq @($inputData.pagefiles).Count) { 'ok' } else { 'partial' })
        pagefiles = $rows; completed_at = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Depth 6 -Compress
}
