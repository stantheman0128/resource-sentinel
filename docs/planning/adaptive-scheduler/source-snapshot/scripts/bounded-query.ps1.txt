# Intended for small-output optional probes, not arbitrary workloads.
function Invoke-BoundedQuery([string]$FileName, [string]$Arguments, [int]$TimeoutMs = 3000) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $FileName
    $info.Arguments = $Arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMs)) {
            $process.Kill()
            throw 'OptionalProbeTimeout'
        }
        if ($process.ExitCode -ne 0) { throw 'OptionalProbeFailed' }
        if (-not $stdout.Wait(500)) { throw 'OptionalProbeOutputTimeout' }
        return $stdout.Result.Trim()
    } finally { $process.Dispose() }
}
