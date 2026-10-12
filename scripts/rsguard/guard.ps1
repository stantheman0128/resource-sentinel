$ErrorActionPreference='Stop'
$log='C:\ProgramData\RSGuard\guard.log'
function L($m){ "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m" | Add-Content -LiteralPath $log }
try {
  # 1) re-enable any disabled sentinel tasks
  foreach($n in 'ResourceSentinel','ResourceSentinelWatchdog'){
    $t=Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
    if(-not $t){ L "MISSING $n"; continue }
    if($t.State -eq 'Disabled'){ Enable-ScheduledTask -TaskName $n | Out-Null; L "re-enabled $n" }
  }
  # 2) check status freshness
  $f='C:\Users\stans\.resource-sentinel\status.json'
  $age = if(Test-Path $f){ [int]((Get-Date)-(Get-Item $f).LastWriteTime).TotalSeconds } else { 999999 }
  if($age -le 300){ L "ok age=${age}s"; return }
  # 3) stale: find how long collector procs have been alive
  $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" |
           Where-Object { $_.CommandLine -match 'collect-scheduled\.ps1|collect\.ps1' }
  $now=Get-Date
  $stuck = $procs | Where-Object { ($now - $_.CreationDate).TotalSeconds -gt 240 }
  if($stuck){
    foreach($s in $stuck){ try{ Stop-Process -Id $s.ProcessId -Force; L "killed stuck collector pid=$($s.ProcessId) ageSec=$([int](($now-$s.CreationDate).TotalSeconds))" }catch{ L "kill failed pid=$($s.ProcessId): $($_.Exception.Message)" } }
    Start-Sleep 2
  }
  # 4) force a fresh run
  Start-ScheduledTask -TaskName ResourceSentinel
  L "status stale age=${age}s -> restarted collector (stuck killed: $(@($stuck).Count))"
} catch {
  L "ERROR $($_.Exception.Message)"
} finally {
  if((Get-Item $log -ErrorAction SilentlyContinue).Length -gt 2MB){ Move-Item $log "$log.old" -Force }
}
