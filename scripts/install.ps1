<#
.SYNOPSIS
    Install the BTGoogle gate into a Google Antigravity configuration.

.DESCRIPTION
    The work is done by scripts/pin_hook.py, so Windows and CI run the same
    logic. The gate keeps ONE name forever (hooks/scope_gate_v2.py): installing
    a new fix copies new CONTENT over that same file. The version is never
    bumped and hooks.json is never repointed at scope_gate_v3.py.

    The gate, its store, noise.json (merged, never shrunk) and the example
    programs are placed in %USERPROFILE%\.gemini\config, and the hooks.json
    entry is merged in place, backed up first.

.NOTES
    Run from the repository root:

        powershell -ExecutionPolicy Bypass -File scripts/install.ps1
        powershell -ExecutionPolicy Bypass -File scripts/install.ps1 -DryRun
        powershell -ExecutionPolicy Bypass -File scripts/install.ps1 -Check
#>

param(
    [switch]$DryRun,
    [switch]$Check
)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$python = (Get-Command python -ErrorAction Stop).Source
$script = Join-Path $repo "scripts\pin_hook.py"

if (-not (Test-Path -LiteralPath $script)) {
    throw "missing $script"
}

$arguments = @($script)
if ($Check) { $arguments += "--check" }
elseif ($DryRun) { $arguments += "--dry-run" }

& $python @arguments
exit $LASTEXITCODE
