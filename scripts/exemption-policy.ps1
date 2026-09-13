# Collector helpers. Identity and expiry are rechecked at the point of mutation.
function Test-SentinelExemption($Process, $Exemptions, [double]$NowEpoch) {
    $key = [string]$Process.Id
    if (-not $Exemptions.ContainsKey($key)) { return $false }
    $row = $Exemptions[$key]
    if ([double]$row.expires_at -le $NowEpoch) { return $false }
    try {
        $started = ($Process.StartTime.ToUniversalTime() - [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).TotalSeconds
        return [math]::Abs($started - [double]$row.started) -lt 0.01
    } catch { return $false }
}

function Restore-SentinelExemptProcess($Process, $Demoted) {
    $key = [string]$Process.Id
    # Only undo recorded Sentinel CPU changes; never raise to admin/realtime.
    if ([string]$Process.PriorityClass -eq 'BelowNormal') {
        $target = 'Normal'
        if ($Demoted.ContainsKey($key)) { $target = $Demoted[$key] }
        $Process.PriorityClass = $target
    }
    $Demoted.Remove($key)
    Set-IoPriority $Process 2
}
