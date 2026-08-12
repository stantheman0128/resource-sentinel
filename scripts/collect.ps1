# Resource Sentinel - collector (spec step 1)
# Single-shot: measures machine + agent process trees, writes status files, exits.
# Scheduling is external (spec step 2). ASCII only to avoid PS 5.1 BOM issues.
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
        system_drive   = 'C:'
        agent_roots    = @('claude.exe', 'cursor.exe', 'codex.exe')
    }
    ($defaults | ConvertTo-Json) | Out-File $configPath -Encoding ascii
}
$config = Get-Content $configPath -Raw | ConvertFrom-Json
$cores = [Environment]::ProcessorCount

# ---------- process snapshot 1 (cpu time baseline) ----------
$snap1 = @{}
Get-CimInstance Win32_Process |
    ForEach-Object { $snap1[$_.ProcessId] = $_.KernelModeTime + $_.UserModeTime }
$t1 = Get-Date

# ---------- total CPU (blocks ~1s; doubles as the per-tree delta window) ----------
# NOTE: never use Win32_Processor.LoadPercentage (measured unreliable on this box).
$cpuTotal = $null
try {
    $cpuTotal = [math]::Round(
        (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue, 1)
} catch {
    $cpuTotal = $null   # fallback computed from process deltas below
}

# ---------- process snapshot 2 (tree building + cpu delta) ----------
$procs = Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, WorkingSetSize, KernelModeTime, UserModeTime
$t2 = Get-Date
$windowTicks = ($t2 - $t1).Ticks   # 100ns units, same as Win32_Process cpu times
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
    if (-not $snap1.ContainsKey($p.ProcessId)) { return 0.0 }  # started inside window
    $delta = ($p.KernelModeTime + $p.UserModeTime) - $snap1[$p.ProcessId]
    if ($delta -lt 0) { return 0.0 }                            # PID reuse
    return [math]::Round(($delta / $windowTicks) / $cores * 100, 1)
}

if ($null -eq $cpuTotal) {
    $sum = 0.0
    foreach ($p in $procs) { $sum += (Get-ProcCpuPct $p) }
    $cpuTotal = [math]::Round([math]::Min($sum, 100), 1)
}

# ---------- agent tree roots: agent-named proc with no agent-named ancestor ----------
$agentNames = @($config.agent_roots | ForEach-Object { $_.ToLower() })
$roots = @()
foreach ($p in $procs) {
    if ($agentNames -notcontains $p.Name.ToLower()) { continue }
    $isRoot = $true
    $cur = $p.ParentProcessId
    $hops = 0
    $seen = @{}
    while ($byId.ContainsKey($cur) -and $hops -lt 64 -and -not $seen.ContainsKey($cur)) {
        $seen[$cur] = $true
        if ($agentNames -contains $byId[$cur].Name.ToLower()) { $isRoot = $false; break }
        $cur = $byId[$cur].ParentProcessId
        $hops++
    }
    if ($isRoot) { $roots += $p }
}

# ---------- aggregate each tree (BFS, cycle-guarded) ----------
$trees = @()
foreach ($root in $roots) {
    $ramBytes = [long]0
    $cpuPct = 0.0
    $count = 0
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
        $count++
        if ($children.ContainsKey($pid_)) {
            foreach ($c in $children[$pid_]) { $queue.Enqueue($c) }
        }
    }
    $trees += [PSCustomObject]@{
        root    = $root.Name
        pid     = $root.ProcessId
        ram_mb  = [math]::Round($ramBytes / 1MB, 0)
        cpu_pct = [math]::Round($cpuPct, 1)
        procs   = $count
    }
}
$trees = @($trees | Sort-Object ram_mb -Descending)

$groups = @($trees | Group-Object root | ForEach-Object {
    [PSCustomObject]@{
        app          = $_.Name
        total_ram_mb = [math]::Round(($_.Group | Measure-Object ram_mb -Sum).Sum, 0)
        total_cpu_pct = [math]::Round(($_.Group | Measure-Object cpu_pct -Sum).Sum, 1)
        trees        = $_.Count
    }
} | Sort-Object total_ram_mb -Descending)

# ---------- machine-wide RAM + disks ----------
$os = Get-CimInstance Win32_OperatingSystem
$ramTotalGb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
$ramFreeGb  = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
$ramUsedPct = [math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)

$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    [PSCustomObject]@{
        drive    = $_.DeviceID
        total_gb = [math]::Round($_.Size / 1GB, 1)
        free_gb  = [math]::Round($_.FreeSpace / 1GB, 1)
    }
})
$sysDisk = $disks | Where-Object { $_.drive -eq $config.system_drive } | Select-Object -First 1
$sysFreeGb = if ($sysDisk) { $sysDisk.free_gb } else { 999 }

# ---------- samples.csv append + 5-min CPU average ----------
$samplesPath = Join-Path $dataDir 'samples.csv'
$now = Get-Date
$nowStr = $now.ToString('yyyy-MM-dd HH:mm:ss')
if (-not (Test-Path $samplesPath)) {
    'timestamp,cpu_pct,ram_used_pct' | Out-File $samplesPath -Encoding ascii
}
"$nowStr,$cpuTotal,$ramUsedPct" | Out-File $samplesPath -Append -Encoding ascii

$lines = @(Get-Content $samplesPath | Select-Object -Skip 1)
# growth guard until step-4 pruning lands: cap at ~7 days of minutely rows
if ($lines.Count -gt 10200) {
    $keep = $lines | Select-Object -Last 10080
    $tmp = "$samplesPath.tmp"
    @('timestamp,cpu_pct,ram_used_pct') + $keep | Out-File $tmp -Encoding ascii
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
    light        = $light
    cpu_pct      = $cpuTotal
    cpu_5min_avg = $cpu5
    ram          = [ordered]@{ total_gb = $ramTotalGb; free_gb = $ramFreeGb; used_pct = $ramUsedPct }
    disks        = $disks
    agent_groups = $groups
    agent_trees  = @($trees | Select-Object -First 10)
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
foreach ($d in $disks) {
    [void]$md.Add("- Disk $($d.drive) $($d.free_gb) GB free of $($d.total_gb) GB")
}
[void]$md.Add("")
[void]$md.Add("## Agent usage (process trees)")
[void]$md.Add("")
if ($groups.Count -eq 0) {
    [void]$md.Add("(no agent processes found)")
} else {
    [void]$md.Add("| app | RAM MB | CPU % | trees |")
    [void]$md.Add("|---|---|---|---|")
    foreach ($g in $groups) {
        [void]$md.Add("| $($g.app) | $($g.total_ram_mb) | $($g.total_cpu_pct) | $($g.trees) |")
    }
    [void]$md.Add("")
    [void]$md.Add("Top trees:")
    foreach ($t in ($trees | Select-Object -First 6)) {
        [void]$md.Add("- $($t.root) pid=$($t.pid): $($t.ram_mb) MB, $($t.cpu_pct)% CPU, $($t.procs) procs")
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

Write-Output "OK light=$light cpu=$cpuTotal ram=$ramUsedPct sysfree=$sysFreeGb trees=$($trees.Count)"
