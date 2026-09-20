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

function Get-SentinelExemptRestoreIntent($Process, $Demoted) {
    $key = [string]$Process.Id
    $target = 'Normal'
    if ($Demoted.ContainsKey($key)) { $target = $Demoted[$key] }
    # This is only an intent. The common executor must recheck exact identity,
    # scope and current priority while holding POLICY before any native write.
    return @{ priority_action = 'restore'; restore_priority = $target; io_priority = 2; trim = $false }
}
