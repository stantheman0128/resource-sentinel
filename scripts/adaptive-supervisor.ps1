# Resource Sentinel - adaptive supervisor entry point.
# Starts sentinel.adaptive.supervisor_host in the foreground and passes its exit
# code through. The supervisor host starts the guardian, and the helper when a
# helper profile is given, with plain process creation and keeps their creation
# handles as death witnesses.
#
# This script registers no Scheduled Task and changes no configuration. Run it
# from its own task or console, never from the collector task: the collector
# runner may end its whole subtree, and a guardian inside that subtree would
# break the rule that managed work is never killed. On the development machine a
# Scheduled Task child was measured inside a Job (CAPABILITY-RESULTS.md,
# 2026-09-19), so the host refuses there and only a plain console passes.
#
# It has no stop path for a child. It does not call taskkill, Stop-Process or
# any tree kill. Ctrl+C ends the supervisor host only. The guardian and the
# helper keep running and are then unsupervised, which the host reports.
#
# Both directories are required and have no default, so this never points at
# the daily data directory unless the caller types that path.
param(
    [Parameter(Mandatory = $true)][string]$DataDir,
    [Parameter(Mandatory = $true)][string]$JournalDir,
    [string]$GuardianProfile = '',
    [string]$HelperProfile = '',
    [int]$MaxGuardians = 1,
    [int]$MaxHelpers = 1,
    [int]$Iterations = 0,
    [string]$Python = ''
)
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
foreach ($directory in @($DataDir, $JournalDir)) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        [Console]::Error.WriteLine('adaptive_supervisor_directory_missing')
        exit 3
    }
}

# The py launcher creates a Job of its own and assigns python.exe to it, and the
# supervisor host refuses to start inside a Job. So the launcher is only asked
# where the interpreter is, and the host is started from that path directly.
if (-not $Python) {
    try {
        $Python = [string](& py -c 'import sys; print(sys._base_executable or sys.executable)' |
                           Select-Object -First 1)
    } catch {
        $Python = ''
    }
}
$Python = $Python.Trim()
if (-not $Python -or -not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    [Console]::Error.WriteLine('adaptive_supervisor_python_unresolved')
    exit 3
}

$argsList = @(
    '-m', 'sentinel.adaptive.supervisor_host',
    '--data-dir', (Resolve-Path -LiteralPath $DataDir).Path,
    '--journal-dir', (Resolve-Path -LiteralPath $JournalDir).Path,
    '--child-cwd', $repoRoot,
    '--max-guardians', [string]$MaxGuardians,
    '--iterations', [string]$Iterations
)
if ($GuardianProfile) {
    $argsList += @('--profile', (Resolve-Path -LiteralPath $GuardianProfile).Path)
}
if ($HelperProfile) {
    $argsList += @('--helper-profile', (Resolve-Path -LiteralPath $HelperProfile).Path,
                   '--max-helpers', [string]$MaxHelpers)
}

Push-Location -LiteralPath $repoRoot
try {
    & $Python @argsList
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $code
