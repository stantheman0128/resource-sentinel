# Resource Sentinel - collector v0.2
# Single-shot: machine + GPU + agent trees + per-process disk-write attribution.
# Scheduling is external. ASCII only to avoid PS 5.1 BOM issues.
$ErrorActionPreference = 'Stop'

$dataDir = Join-Path $env:USERPROFILE '.resource-sentinel'
if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir | Out-Null }

# ---------- config ----------
$configPath = Join-Path $dataDir 'config.json'
if (-not (Test-Path $configPath)) {
    $defaults = [ordered]@{
        ram_yellow_pct = 75
        ram_red_pct    = 90
        cpu_yellow_pct = 60
        cpu_red_pct    = 85
        disk_yellow_gb = 50
        disk_red_gb    = 20
        disk_event_gb  = 2      # abs free-space change per interval that triggers an event
        system_drive   = 'C:'
        agent_roots    = @('claude.exe', 'cursor.exe', 'codex.exe')
    }
    ($defaults | ConvertTo-Json) | Out-File $configPath -Encoding ascii
}
$config = Get-Content $configPath -Raw | ConvertFrom-Json
if ($null -eq $config.disk_event_gb) {   # migrate v0.1 config
    $config | Add-Member -NotePropertyName disk_event_gb -NotePropertyValue 2
    ($config | ConvertTo-Json) | Out-File $configPath -Encoding ascii
}
$cores = [Environment]::ProcessorCount

# ---------- previous state (for io/disk deltas across runs) ----------
$statePath = Join-Path $dataDir 'state.json'
$prev = $null
if (Test-Path $statePath) {
    try { $prev = Get-Content $statePath -Raw | ConvertFrom-Json } catch { $prev = $null }
}

# ---------- process snapshot 1 (cpu baseline) ----------
$snap1 = @{}
Get-CimInstance Win32_Process |
    ForEach-Object { $snap1[$_.ProcessId] = $_.KernelModeTime + $_.UserModeTime }
$t1 = Get-Date

# ---------- total CPU (blocks ~1s = per-tree cpu delta window) ----------
# NOTE: never use Win32_Processor.LoadPercentage (measured unreliable on this box).
$cpuTotal = $null
try {
    $cpuTotal = [math]::Round(
        (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue, 1)
} catch { $cpuTotal = $null }

# ---------- GPU (nvidia-smi primary, perf counters fallback) ----------
$gpu = [ordered]@{ util_pct = $null; vram_used_mb = $null; vram_total_mb = $null; source = 'none' }
try {
    $smi = & nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits 2>$null
    if ($LASTEXITCODE -eq 0 -and $smi) {
        $parts = ($smi | Select-Object -First 1).Split(',') | ForEach-Object { $_.Trim() }
        $gpu.util_pct      = [double]$parts[0]
        $gpu.vram_used_mb  = [double]$parts[1]
        $gpu.vram_total_mb = [double]$parts[2]
        $gpu.source = 'nvidia-smi'
    }
} catch { }
if ($gpu.source -eq 'none') {
    try {
        $eng = (Get-Counter '\GPU Engine(*engtype_3D)\Utilization Percentage').CounterSamples
        $gpu.util_pct = [math]::Round([math]::Min(($eng | Measure-Object CookedValue -Sum).Sum, 100), 1)
        $mem = (Get-Counter '\GPU Adapter Memory(*)\Dedicated Usage').CounterSamples
        $gpu.vram_used_mb = [math]::Round((($mem | Measure-Object CookedValue -Sum).Sum) / 1MB, 0)
        $gpu.source = 'counters'
    } catch { }
}

# ---------- process snapshot 2 (trees + cpu + io) ----------
$procs = Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, WorkingSetSize,
                  KernelModeTime, UserModeTime, WriteTransferCount, CreationDate
$t2 = Get-Date
$windowTicks = ($t2 - $t1).Ticks
if ($windowTicks -le 0) { $windowTicks = 1 }

$byId = @{}
foreach ($p in $procs) { $byId[$p.ProcessId] = $p }
$children = @{}
foreach ($p in $procs) {
    if (-not $children.ContainsKey($p.ParentProcessId)) {
        $children[$p.ParentProcessId] = New-Object System.Collections.ArrayList
    }
    [void]$children[$p.ParentProcessId].Add($p.ProcessId)
}

function Get-ProcCpuPct($p) {
    if (-not $snap1.ContainsKey($p.ProcessId)) { return 0.0 }
    $delta = ($p.KernelModeTime + $p.UserModeTime) - $snap1[$p.ProcessId]
    if ($delta -lt 0) { return 0.0 }
    return [math]::Round(($delta / $windowTicks) / $cores * 100, 1)
}
if ($null -eq $cpuTotal) {
    $sum = 0.0
    foreach ($p in $procs) { $sum += (Get-ProcCpuPct $p) }
    $cpuTotal = [math]::Round([math]::Min($sum, 100), 1)
}

# ---------- disk-write attribution: delta vs previous run ----------
# WriteTransferCount is cumulative bytes written by the process since it started.
# Delta across runs = bytes written in the interval. PID reuse guarded by CreationDate.
$writeDelta = @{}   # pid -> bytes written since last run
if ($null -ne $prev -and $null -ne $prev.procs) {
    foreach ($p in $procs) {
        $key = [string]$p.ProcessId
        $old = $prev.procs.$key
        if ($null -ne $old -and $old.c -eq [string]$p.CreationDate) {
            $d = [long]$p.WriteTransferCount - [long]$old.w
            if ($d -gt 0) { $writeDelta[$p.ProcessId] = $d }
        }
    }
}

# ---------- agent tree roots ----------
$agentNames = @($config.agent_roots | ForEach-Object { $_.ToLower() })
$roots = @()
foreach ($p in $procs) {
    if ($agentNames -notcontains $p.Name.ToLower()) { continue }
    $isRoot = $true
    $cur = $p.ParentProcessId; $hops = 0; $seen = @{}
    while ($byId.ContainsKey($cur) -and $hops -lt 64 -and -not $seen.ContainsKey($cur)) {
        $seen[$cur] = $true
        if ($agentNames -contains $byId[$cur].Name.ToLower()) { $isRoot = $false; break }
        $cur = $byId[$cur].ParentProcessId; $hops++
    }
    if ($isRoot) { $roots += $p }
}

# ---------- aggregate trees (BFS, cycle-guarded); record pid->tree for attribution ----------
$treeOf = @{}
$trees = @()
foreach ($root in $roots) {
    $label = "$($root.Name)#$($root.ProcessId)"
    $ramBytes = [long]0; $cpuPct = 0.0; $ioBytes = [long]0; $count = 0
    $queue = New-Object System.Collections.Queue
    $visited = @{}
    $queue.Enqueue($root.ProcessId)
    while ($queue.Count -gt 0) {
        $pid_ = $queue.Dequeue()
        if ($visited.ContainsKey($pid_)) { continue }
        $visited[$pid_] = $true
        if (-not $byId.ContainsKey($pid_)) { continue }
        $node = $byId[$pid_]
        $ramBytes += [long]$node.WorkingSetSize
        $cpuPct += (Get-ProcCpuPct $node)
        if ($writeDelta.ContainsKey($pid_)) { $ioBytes += $writeDelta[$pid_] }
        $treeOf[$pid_] = $label
        $count++
        if ($children.ContainsKey($pid_)) {
            foreach ($c in $children[$pid_]) { $queue.Enqueue($c) }
        }
    }
    $trees += [PSCustomObject]@{
        root = $root.Name; pid = $root.ProcessId
        ram_mb = [math]::Round($ramBytes / 1MB, 0)
        cpu_pct = [math]::Round($cpuPct, 1)
        write_mb = [math]::Round($ioBytes / 1MB, 1)
        procs = $count
    }
}
$trees = @($trees | Sort-Object ram_mb -Descending)
$groups = @($trees | Group-Object root | ForEach-Object {
    [PSCustomObject]@{
        app = $_.Name
        total_ram_mb  = [math]::Round(($_.Group | Measure-Object ram_mb -Sum).Sum, 0)
        total_cpu_pct = [math]::Round(($_.Group | Measure-Object cpu_pct -Sum).Sum, 1)
        write_mb      = [math]::Round(($_.Group | Measure-Object write_mb -Sum).Sum, 1)
        trees = $_.Count
    }
} | Sort-Object total_ram_mb -Descending)

# ---------- top disk writers this interval (any process, not just agents) ----------
$topWriters = @()
foreach ($pid_ in ($writeDelta.Keys | Sort-Object { $writeDelta[$_] } -Descending | Select-Object -First 8)) {
    $p = $byId[$pid_]
    $tw = [ordered]@{
        name = $p.Name; pid = $pid_
        mb = [math]::Round($writeDelta[$pid_] / 1MB, 1)
    }
    if ($treeOf.ContainsKey($pid_)) { $tw.agent_tree = $treeOf[$pid_] }
    $topWriters += [PSCustomObject]$tw
}
$topWriters = @($topWriters | Where-Object { $_.mb -ge 1 })   # noise floor 1 MB

# ---------- machine RAM + disks ----------
$os = Get-CimInstance Win32_OperatingSystem
$ramTotalGb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
$ramFreeGb  = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
$ramUsedPct = [math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    [PSCustomObject]@{
        drive = $_.DeviceID
        total_gb = [math]::Round($_.Size / 1GB, 1)
        free_gb  = [math]::Round($_.FreeSpace / 1GB, 1)
    }
})
$sysDisk = $disks | Where-Object { $_.drive -eq $config.system_drive } | Select-Object -First 1
$sysFreeGb = if ($sysDisk) { $sysDisk.free_gb } else { 999 }

# ---------- disk-change events ----------
$eventsPath = Join-Path $dataDir 'events.log'
$now = Get-Date
$nowStr = $now.ToString('yyyy-MM-dd HH:mm:ss')
if ($null -ne $prev -and $null -ne $prev.drives) {
    foreach ($d in $disks) {
        $oldFree = $prev.drives.($d.drive)
        if ($null -eq $oldFree) { continue }
        $delta = [math]::Round($d.free_gb - [double]$oldFree, 2)
        if ([math]::Abs($delta) -ge [double]$config.disk_event_gb) {
            $evt = [ordered]@{
                ts = $nowStr; type = 'disk_delta'; drive = $d.drive
                delta_gb = $delta; free_gb = $d.free_gb
                top_writers = $topWriters
            }
            ($evt | ConvertTo-Json -Depth 4 -Compress) | Add-Content $eventsPath -Encoding ascii
        }
    }
}
if ((Test-Path $eventsPath) -and (Get-Item $eventsPath).Length -gt 2MB) {
    $keep = Get-Content $eventsPath | Select-Object -Last 1000
    $tmp = "$eventsPath.tmp"; $keep | Out-File $tmp -Encoding ascii
    Move-Item -Force $tmp $eventsPath
}

# ---------- save state for next run ----------
$stateProcs = @{}
foreach ($p in $procs) {
    $stateProcs[[string]$p.ProcessId] = @{
        w = [long]$p.WriteTransferCount
        c = [string]$p.CreationDate
        n = $p.Name
    }
}
$stateDrives = @{}
foreach ($d in $disks) { $stateDrives[$d.drive] = $d.free_gb }
$state = @{ ts = $nowStr; drives = $stateDrives; procs = $stateProcs }
$tmp = "$statePath.tmp"
($state | ConvertTo-Json -Depth 4 -Compress) | Out-File $tmp -Encoding ascii
Move-Item -Force $tmp $statePath

# ---------- samples.csv + 5-min cpu avg ----------
$samplesPath = Join-Path $dataDir 'samples.csv'
if (-not (Test-Path $samplesPath)) {
    'timestamp,cpu_pct,ram_used_pct,gpu_pct' | Out-File $samplesPath -Encoding ascii
}
$gpuStr = if ($null -ne $gpu.util_pct) { $gpu.util_pct } else { '' }
"$nowStr,$cpuTotal,$ramUsedPct,$gpuStr" | Out-File $samplesPath -Append -Encoding ascii
$lines = @(Get-Content $samplesPath | Select-Object -Skip 1)
if ($lines.Count -gt 10200) {
    $keep = $lines | Select-Object -Last 10080
    $tmp = "$samplesPath.tmp"
    @('timestamp,cpu_pct,ram_used_pct,gpu_pct') + $keep | Out-File $tmp -Encoding ascii
    Move-Item -Force $tmp $samplesPath
    $lines = $keep
}
$cutoff = $now.AddMinutes(-5)
$recent = @()
foreach ($ln in ($lines | Select-Object -Last 10)) {
    $parts = $ln.Split(',')
    if ($parts.Count -lt 2) { continue }
    try {
        $ts = [datetime]::ParseExact($parts[0], 'yyyy-MM-dd HH:mm:ss', $null)
        if ($ts -ge $cutoff) { $recent += [double]$parts[1] }
    } catch { }
}
$cpu5 = if ($recent.Count -gt 0) {
    [math]::Round(($recent | Measure-Object -Average).Average, 1)
} else { $cpuTotal }

# ---------- light ----------
$light = 'GREEN'
if ($ramUsedPct -ge $config.ram_yellow_pct -or $cpu5 -ge $config.cpu_yellow_pct -or
    $sysFreeGb -le $config.disk_yellow_gb) { $light = 'YELLOW' }
if ($ramUsedPct -ge $config.ram_red_pct -or $cpu5 -ge $config.cpu_red_pct -or
    $sysFreeGb -le $config.disk_red_gb) { $light = 'RED' }

# ---------- status.json (atomic) ----------
$statusJsonPath = Join-Path $dataDir 'status.json'
$status = [ordered]@{
    generated_at = $nowStr
    light = $light
    cpu_pct = $cpuTotal
    cpu_5min_avg = $cpu5
    ram = [ordered]@{ total_gb = $ramTotalGb; free_gb = $ramFreeGb; used_pct = $ramUsedPct }
    gpu = $gpu
    disks = $disks
    agent_groups = $groups
    agent_trees = @($trees | Select-Object -First 10)
    top_disk_writers_interval = $topWriters
}
$tmp = "$statusJsonPath.tmp"
($status | ConvertTo-Json -Depth 5) | Out-File $tmp -Encoding ascii
Move-Item -Force $tmp $statusJsonPath

# ---------- status.md (atomic) ----------
$statusMdPath = Join-Path $dataDir 'status.md'
$md = New-Object System.Collections.ArrayList
[void]$md.Add("# Resource Sentinel status")
[void]$md.Add("")
[void]$md.Add("Generated: $nowStr (stale if older than 5 minutes)")
[void]$md.Add("")
[void]$md.Add("## Light: $light")
[void]$md.Add("")
[void]$md.Add("- CPU now: ${cpuTotal}% | 5-min avg: ${cpu5}%")
[void]$md.Add("- RAM: ${ramUsedPct}% used (${ramFreeGb} GB free of ${ramTotalGb} GB)")
if ($null -ne $gpu.util_pct) {
    [void]$md.Add("- GPU: $($gpu.util_pct)% | VRAM $($gpu.vram_used_mb)/$($gpu.vram_total_mb) MB")
}
foreach ($d in $disks) {
    [void]$md.Add("- Disk $($d.drive) $($d.free_gb) GB free of $($d.total_gb) GB")
}
[void]$md.Add("")
[void]$md.Add("## Agent usage (process trees)")
[void]$md.Add("")
if ($groups.Count -eq 0) {
    [void]$md.Add("(no agent processes found)")
} else {
    [void]$md.Add("| app | RAM MB | CPU % | disk write MB (last interval) | trees |")
    [void]$md.Add("|---|---|---|---|---|")
    foreach ($g in $groups) {
        [void]$md.Add("| $($g.app) | $($g.total_ram_mb) | $($g.total_cpu_pct) | $($g.write_mb) | $($g.trees) |")
    }
}
if ($topWriters.Count -gt 0) {
    [void]$md.Add("")
    [void]$md.Add("## Top disk writers since last run")
    foreach ($w in $topWriters) {
        $tag = if ($w.PSObject.Properties['agent_tree']) { " [$($w.agent_tree)]" } else { "" }
        [void]$md.Add("- $($w.name) pid=$($w.pid): $($w.mb) MB$tag")
    }
}
[void]$md.Add("")
[void]$md.Add("## Guidance")
switch ($light) {
    'GREEN'  { [void]$md.Add("Normal operation. Heavy tasks OK.") }
    'YELLOW' { [void]$md.Add("Machine under load. Defer or slow down heavy tasks (builds, installs, test suites, new subagents). Run heavy commands with BelowNormal priority.") }
    'RED'    { [void]$md.Add("Machine critically loaded. Light operations only (reads, small edits). Do NOT start builds, installs, or new agent sessions until light clears.") }
}
$tmp = "$statusMdPath.tmp"
($md -join "`r`n") | Out-File $tmp -Encoding ascii
Move-Item -Force $tmp $statusMdPath

# ---------- dashboard data (data.js) + static page copy ----------
$dataJsPath = Join-Path $dataDir 'data.js'
$samplesTail = @($lines | Select-Object -Last 180)
# manual JSON array build: PS 5.1 ConvertTo-Json collapses 1-element arrays
$samplesJs = if ($samplesTail.Count -gt 0) {
    '["' + ($samplesTail -join '","') + '"]'
} else { '[]' }
$evJs = '[]'
if (Test-Path $eventsPath) {
    $evLines = @(Get-Content $eventsPath | Select-Object -Last 20)
    if ($evLines.Count -gt 0) { $evJs = '[' + ($evLines -join ',') + ']' }
}
$js = @(
    'window.SENTINEL_STATUS=' + ($status | ConvertTo-Json -Depth 5 -Compress) + ';'
    'window.SENTINEL_SAMPLES=' + $samplesJs + ';'
    'window.SENTINEL_EVENTS=' + $evJs + ';'
)
$tmp = "$dataJsPath.tmp"
($js -join "`n") | Out-File $tmp -Encoding ascii
Move-Item -Force $tmp $dataJsPath

$dashSrc = Join-Path (Split-Path $PSScriptRoot -Parent) 'dashboard\dashboard.html'
$dashDst = Join-Path $dataDir 'dashboard.html'
if ((Test-Path $dashSrc) -and (
        -not (Test-Path $dashDst) -or
        (Get-Item $dashSrc).LastWriteTime -gt (Get-Item $dashDst).LastWriteTime)) {
    Copy-Item $dashSrc $dashDst -Force
}

Write-Output "OK light=$light cpu=$cpuTotal ram=$ramUsedPct gpu=$($gpu.util_pct) sysfree=$sysFreeGb trees=$($trees.Count) writers=$($topWriters.Count)"
