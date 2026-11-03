# Sweep verification - run elevated, writes docs/verification.md
# Every command's output and exit code is recorded so a claim can be checked.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# Derive the project root from this script's location. A hardcoded path meant
# this harness silently did nothing after the project moved - and still exited 0.
$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $root "sweep"))) {
    Write-Error "Cannot locate the Sweep project from '$PSScriptRoot'"
    exit 2
}

$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) {
    $candidate = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
    if (Test-Path -LiteralPath $candidate) { $py = $candidate }
}
if (-not $py) {
    Write-Error "No python interpreter found on PATH"
    exit 2
}

$report = Join-Path $root "docs\verification.md"
if (-not (Test-Path -LiteralPath (Split-Path -Parent $report))) {
    Write-Error "Report directory does not exist: $(Split-Path -Parent $report)"
    exit 2
}

Set-Location $root
Write-Host "root: $root"
Write-Host "py  : $py"

function W($text) {
    Add-Content -LiteralPath $report -Value $text -Encoding utf8
    Write-Host $text
}

function Run($title, $cmd) {
    W ""
    W "### $title"
    W ""
    W '```'
    $out = & cmd /c "$cmd 2>&1"
    $code = $LASTEXITCODE
    $text = ($out | Out-String).TrimEnd()
    if ($text.Length -gt 4000) { $text = $text.Substring(0, 4000) + "`n... (truncated)" }
    if ($text) { W $text }
    W '```'
    W ""
    W ("**exit code:** ``{0}``" -f $code)
    return $code
}

"# Verification run" | Set-Content -LiteralPath $report -Encoding utf8
W ""
W ("Generated: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
W ""

# ---------------------------------------------------------------- identity
W "## Environment"
W ""
$who = whoami
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
W ("- user: ``{0}``" -f $who)
W ("- elevated: **{0}**" -f $isAdmin)
W ("- python: ``{0}``" -f (& $py --version 2>&1))
W ("- os: {0}" -f (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption)
$env:SWEEP_HOME = $null

# ------------------------------------------------------------------- tests
Run "Full test suite" "`"$py`" -m unittest discover -s tests"

# --------------------------------------------------------------- scheduler
Run "Schedule: install" "`"$py`" -m sweep schedule --frequency daily --at 03:00"
Run "Schedule: status" "`"$py`" -m sweep schedule --status"
Run "Schedule: remove" "`"$py`" -m sweep schedule --remove"

# ------------------------------------------------------------ secure erase
$scratch = Join-Path $root ".verify-scratch"
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
1..3 | ForEach-Object {
    [System.IO.File]::WriteAllBytes((Join-Path $scratch "secret$_.bin"), (New-Object byte[] 4096))
}
Run "Secure erase (dry run)" "`"$py`" -m sweep secure `"$scratch`""
Run "Secure erase (apply)" "`"$py`" -m sweep secure `"$scratch`" --apply --passes 1"
$left = @(Get-ChildItem -LiteralPath $scratch -File -ErrorAction SilentlyContinue).Count
W ""
W ("**files remaining in scratch:** ``{0}`` (0 means wipe worked)" -f $left)
Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------- windows update
Run "Windows Update: enumerate (read-only)" "`"$py`" -m sweep windows-update"

# ----------------------------------------------------------------- drivers
Run "Drivers: inventory" "`"$py`" -m sweep drivers"
Run "Drivers: check Windows Update (read-only)" "`"$py`" -m sweep drivers --check"

# ---------------------------------------------------------- software update
Run "Software: winget diagnose + list" "`"$py`" -m sweep updates"

# -------------------------------------------------------------- management
Run "Update: unified preview (no --apply)" "`"$py`" -m sweep update"

# ------------------------------------------------------------------ engine
Run "Scan (default rules)" "`"$py`" -m sweep scan --quiet"
Run "Health" "`"$py`" -m sweep health --no-save"

# -------------------------------------------------------------------- done
W ""
W "---"
W ""
W ("Finished: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Write-Host ""
if (-not (Test-Path -LiteralPath $report)) {
    Write-Error "No report was written - verification did not run"
    exit 1
}
Write-Host "Verification complete -> $report"
exit 0
