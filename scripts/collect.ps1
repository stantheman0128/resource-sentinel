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
        ram_yellow_pct  = 75
        ram_orange_pct  = 85
        ram_red_pct     = 92
        cpu_yellow_pct  = 60
        cpu_orange_pct  = 75
        cpu_red_pct     = 88
        disk_yellow_gb  = 50
        disk_orange_gb  = 35
        disk_red_gb     = 20
        disk_event_gb   = 2      # abs free-space change per interval that triggers an event
        system_drive    = 'C:'
        agent_roots     = @('claude.exe', 'cursor.exe', 'codex.exe')
    }
    ($defaults | ConvertTo-Json) | Out-File $configPath -Encoding ascii
}
$config = Get-Content $configPath -Raw | ConvertFrom-Json
# migrate older configs: add any missing keys
$migrations = @{
    disk_event_gb = 2; ram_orange_pct = 85; cpu_orange_pct = 75; disk_orange_gb = 35
}
$migrated = $false
foreach ($k in $migrations.Keys) {
    if ($null -eq $config.$k) {
        $config | Add-Member -NotePropertyName $k -NotePropertyValue $migrations[$k]
        $migrated = $true
    }
}
if ($migrated) { ($config | ConvertTo-Json) | Out-File $configPath -Encoding ascii }
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

# ---------- session->repo attribution (sessions.json written by agent hooks) ----------
$sessionsPath = Join-Path $dataDir 'sessions.json'
$sessions = $null
if (Test-Path $sessionsPath) {
    try { $sessions = Get-Content $sessionsPath -Raw | ConvertFrom-Json } catch { $sessions = $null }
}
$repoOfTree = @{}
if ($null -ne $sessions) {
    foreach ($prop in $sessions.PSObject.Properties) {
        $spid = [uint32]0
        if ([uint32]::TryParse($prop.Name, [ref]$spid) -and $treeOf.ContainsKey($spid)) {
            $repoOfTree[$treeOf[$spid]] = [string]$prop.Value.repo
        }
    }
}
foreach ($t in $trees) {
    $lbl = "$($t.root)#$($t.pid)"
    if ($repoOfTree.ContainsKey($lbl)) {
        $t | Add-Member -NotePropertyName repo -NotePropertyValue $repoOfTree[$lbl] -Force
    }
}

# ---------- per-repo peak ledger: track live peaks, finalize dead trees ----------
$peaks = @{}
if ($null -ne $prev -and $null -ne $prev.peaks) {
    foreach ($pp in $prev.peaks.PSObject.Properties) {
        $peaks[$pp.Name] = @{ repo = $pp.Value.repo; peak_mb = [double]$pp.Value.peak_mb }
    }
}
$aliveLabels = @{}
foreach ($t in $trees) {
    $lbl = "$($t.root)#$($t.pid)"
    $aliveLabels[$lbl] = $true
    $repo = $null
    if ($repoOfTree.ContainsKey($lbl)) { $repo = $repoOfTree[$lbl] }
    elseif ($peaks.ContainsKey($lbl) -and $null -ne $peaks[$lbl].repo) { $repo = $peaks[$lbl].repo }
    $pk = [double]$t.ram_mb
    if ($peaks.ContainsKey($lbl) -and [double]$peaks[$lbl].peak_mb -gt $pk) { $pk = [double]$peaks[$lbl].peak_mb }
    $peaks[$lbl] = @{ repo = $repo; peak_mb = $pk }
}
$historyPath = Join-Path $dataDir 'history.json'
$histTable = @{}
if (Test-Path $historyPath) {
    try {
        $h = Get-Content $historyPath -Raw | ConvertFrom-Json
        foreach ($hp in $h.PSObject.Properties) { $histTable[$hp.Name] = $hp.Value }
    } catch { }
}
$histChanged = $false
foreach ($lbl in @($peaks.Keys)) {
    if ($aliveLabels.ContainsKey($lbl)) { continue }
    $entry = $peaks[$lbl]
    $peaks.Remove($lbl)
    if ($null -eq $entry.repo -or [double]$entry.peak_mb -lt 100) { continue }   # noise floor
    $repo = [string]$entry.repo
    $rec = @()
    if ($histTable.ContainsKey($repo) -and $null -ne $histTable[$repo].recent) {
        $rec = @($histTable[$repo].recent)
    }
    $rec += [PSCustomObject]@{ ts = $nowStr; peak_mb = [math]::Round([double]$entry.peak_mb, 0) }
    if ($rec.Count -gt 20) { $rec = @($rec | Select-Object -Last 20) }
    $sorted = @($rec | ForEach-Object { [double]$_.peak_mb } | Sort-Object)
    $mid = [int][math]::Floor($sorted.Count / 2)
    $typ = if ($sorted.Count % 2 -eq 1) { $sorted[$mid] }
           else { [math]::Round(($sorted[$mid - 1] + $sorted[$mid]) / 2, 0) }
    $oldPeak = 0.0
    if ($histTable.ContainsKey($repo)) { $oldPeak = ($histTable[$repo].peak_ram_mb) -as [double] }
    $histTable[$repo] = [PSCustomObject]@{
        peak_ram_mb     = [math]::Round([math]::Max($oldPeak, [double]$entry.peak_mb), 0)
        typical_peak_mb = $typ
        recent          = $rec
    }
    $histChanged = $true
}
if ($histChanged) {
    $tmp = "$historyPath.tmp"
    ($histTable | ConvertTo-Json -Depth 4) | Out-File $tmp -Encoding ascii
    Move-Item -Force $tmp $historyPath
}

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

# ---------- light (4 levels; worst dimension wins) ----------
# RAM/CPU judged in percent; disk judged in absolute free GB on the system drive.
$light = 'GREEN'
if ($ramUsedPct -ge $config.ram_yellow_pct -or $cpu5 -ge $config.cpu_yellow_pct -or
    $sysFreeGb -le $config.disk_yellow_gb) { $light = 'YELLOW' }
if ($ramUsedPct -ge $config.ram_orange_pct -or $cpu5 -ge $config.cpu_orange_pct -or
    $sysFreeGb -le $config.disk_orange_gb) { $light = 'ORANGE' }
if ($ramUsedPct -ge $config.ram_red_pct -or $cpu5 -ge $config.cpu_red_pct -or
    $sysFreeGb -le $config.disk_red_gb) { $light = 'RED' }

# ---------- telegram alert: sustained RED -> alert; recovery -> all-clear ----------
$alertState = @{ streak = 0; last_ts = [double]0; active = $false }
if ($null -ne $prev -and $null -ne $prev.alert) {
    $alertState.streak  = [int]$prev.alert.streak
    $alertState.last_ts = [double]$prev.alert.last_ts
    $alertState.active  = [bool]$prev.alert.active
}
if ($light -eq 'RED') { $alertState.streak++ } else { $alertState.streak = 0 }

$tg = $config.telegram
if ($null -ne $tg -and $tg.enabled) {
    $nowEpochA = [double]((Get-Date).ToUniversalTime() - (Get-Date '1970-01-01')).TotalSeconds
    $redAfter = 5;   if ($null -ne $tg.red_after_samples) { $redAfter = [int]$tg.red_after_samples }
    $cooldown = 60;  if ($null -ne $tg.cooldown_min) { $cooldown = [int]$tg.cooldown_min }
    $fire = ($alertState.streak -ge $redAfter -and
             ($nowEpochA - $alertState.last_ts) -gt $cooldown * 60)
    $clear = ($alertState.active -and $light -eq 'GREEN')
    if ($fire -or $clear) {
        $token = $null; $chat = $null
        try {
            foreach ($ln in (Get-Content $tg.env_path)) {
                if ($ln -match '^TELEGRAM_BOT_TOKEN=(.+)$') { $token = $Matches[1].Trim() }
                if ($ln -match '^TELEGRAM_ALLOWED_IDS=(.+)$') { $chat = $Matches[1].Split(',')[0].Trim() }
            }
        } catch { }
        if ($null -ne $tg.chat_id) { $chat = [string]$tg.chat_id }
        if ($token -and $chat) {
            $topTree = ''
            if ($trees.Count -gt 0) {
                $topTree = " | top: $($trees[0].root)#$($trees[0].pid) $($trees[0].ram_mb)MB"
            }
            $msg = if ($fire) {
                "[sentinel] RED for $($alertState.streak) min. CPU5m $cpu5% RAM $ramUsedPct% C: $sysFreeGb GB free$topTree"
            } else {
                "[sentinel] recovered: GREEN. CPU5m $cpu5% RAM $ramUsedPct%"
            }
            try {
                Invoke-RestMethod -Uri "https://api.telegram.org/bot$token/sendMessage" `
                    -Method Post -TimeoutSec 5 `
                    -Body @{ chat_id = $chat; text = $msg } | Out-Null
                if ($fire) { $alertState.last_ts = $nowEpochA; $alertState.active = $true }
                if ($clear) { $alertState.active = $false }
            } catch { }
        }
    }
}

# ---------- central throttle: demote agent trees to BelowNormal on ORANGE/RED ----------
# Works on ANY agent process tree regardless of whether the agent reads status.md.
# Never kills; only lowers CPU scheduling priority. Restores on GREEN (hysteresis).
$demoted = @{}
if ($null -ne $prev -and $null -ne $prev.demoted) {
    foreach ($dp in $prev.demoted.PSObject.Properties) { $demoted[$dp.Name] = [string]$dp.Value }
}
$throttleOn = ($light -eq 'ORANGE' -or $light -eq 'RED')
if ($null -ne $config.throttle_enable -and -not $config.throttle_enable) { $throttleOn = $false }
if ($throttleOn) {
    foreach ($pid_ in $treeOf.Keys) {
        $key = [string]$pid_
        try {
            $proc = Get-Process -Id $pid_ -ErrorAction Stop
            $orig = [string]$proc.PriorityClass
            if ($orig -eq 'Normal' -or $orig -eq 'AboveNormal' -or $orig -eq 'High') {
                $proc.PriorityClass = 'BelowNormal'
                if (-not $demoted.ContainsKey($key)) { $demoted[$key] = $orig }
            }
        } catch { }
    }
} elseif ($light -eq 'GREEN') {
    # self-healing restore: raise ANY BelowNormal agent-tree process, map or not.
    # (a lost map must never leave sessions stuck at BelowNormal forever)
    foreach ($pid_ in $treeOf.Keys) {
        $key = [string]$pid_
        try {
            $proc = Get-Process -Id $pid_ -ErrorAction Stop
            if ([string]$proc.PriorityClass -eq 'BelowNormal') {
                $target = 'Normal'
                if ($demoted.ContainsKey($key)) { $target = $demoted[$key] }
                $proc.PriorityClass = $target
            }
        } catch { }
    }
    $demoted = @{}
}
# drop entries for dead pids so the map never grows unbounded
foreach ($key in @($demoted.Keys)) {
    if (-not $byId.ContainsKey([uint32]$key)) { $demoted.Remove($key) }
}
# live count of BelowNormal agent procs for display (never trust the map for UI)
$demotedNow = 0
try {
    $prios = @{}
    Get-Process | ForEach-Object {
        try { $prios[[uint32]$_.Id] = [string]$_.PriorityClass } catch { }
    }
    foreach ($pid_ in $treeOf.Keys) {
        if ($prios.ContainsKey($pid_) -and $prios[$pid_] -eq 'BelowNormal') { $demotedNow++ }
    }
} catch { }

# ---------- heavy-slot cleanup (arbiter state written by sentinel-gate.py) ----------
$slotsPath = Join-Path $dataDir 'slots.json'
$activeSlots = @()
if (Test-Path $slotsPath) {
    try {
        $sd = Get-Content $slotsPath -Raw | ConvertFrom-Json
        $nowEpoch = [double](Get-Date -UFormat %s)
        foreach ($sl in @($sd.slots)) {
            if ($null -eq $sl) { continue }
            $ttl = 15; if ($null -ne $sl.ttl_min) { $ttl = [double]$sl.ttl_min }
            if (($nowEpoch - [double]$sl.ts) -gt $ttl * 60) { continue }
            if (-not $byId.ContainsKey([uint32]$sl.pid)) { continue }
            $activeSlots += $sl
        }
        if ($activeSlots.Count -ne @($sd.slots).Count) {
            $tmp = "$slotsPath.tmp"
            (@{ slots = $activeSlots } | ConvertTo-Json -Depth 3 -Compress) | Out-File $tmp -Encoding ascii
            Move-Item -Force $tmp $slotsPath
        }
    } catch { }
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
$state = @{ ts = $nowStr; drives = $stateDrives; procs = $stateProcs; peaks = $peaks; demoted = $demoted; alert = $alertState }
$tmp = "$statePath.tmp"
($state | ConvertTo-Json -Depth 4 -Compress) | Out-File $tmp -Encoding ascii
Move-Item -Force $tmp $statePath

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
    heavy_slots = $activeSlots
    throttle = [ordered]@{ active = $throttleOn; demoted_procs = $demotedNow }
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
[void]$md.Add("## Arbiter")
if ($activeSlots.Count -gt 0) {
    foreach ($sl in $activeSlots) {
        [void]$md.Add("- heavy slot held: pid $($sl.pid) repo=$($sl.repo) cmd=$($sl.cmd)")
    }
} else {
    [void]$md.Add("- heavy slot: free")
}
if ($throttleOn) {
    [void]$md.Add("- central throttle ACTIVE: $($demotedNow) agent processes at BelowNormal to BelowNormal (restored at GREEN)")
}
[void]$md.Add("")
[void]$md.Add("## Guidance")
switch ($light) {
    'GREEN'  { [void]$md.Add("Normal operation. Heavy tasks OK.") }
    'YELLOW' { [void]$md.Add("Load elevated. Heavy tasks (builds, installs, test suites) should run with BelowNormal priority. Avoid launching parallel heavy work.") }
    'ORANGE' { [void]$md.Add("Load tight. Defer new heavy tasks; finish what is running. Anything heavy that must run: BelowNormal priority, one at a time.") }
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
