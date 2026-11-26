<#
.SYNOPSIS
    Send representative PreToolUse payloads through the installed gate.

.DESCRIPTION
    Reads hooks/scope_gate.py from this repository and prints the decision for
    a set of commands, failing when a decision differs from the expected one.
    It does not touch the live Antigravity configuration.

.NOTES
    Run from the repository root:

        powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
#>

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$gate = Join-Path $repo "hooks\scope_gate.py"
$python = (Get-Command python -ErrorAction Stop).Source

# Deliberately no $OutputEncoding override: Windows PowerShell 5.1 pipes UTF-8
# with a BOM, PowerShell 7 pipes it without, and this script should exercise
# whichever one the caller shell really does. The gate strips a BOM from stdin,
# so the decisions must come out the same either way.

$env:BTG_PROGRAMS_DIR = Join-Path $repo "hooks\programs"
$env:BTG_NOISE_FILE = Join-Path $repo "hooks\noise.json"
$env:BTG_LOG_FILE = Join-Path $env:TEMP "btg-verify.log"

$cases = @(
    @{ Label = "python identifier"; CommandLine = 'python -c "import json; json.loads(s)"'; Expected = "allow" },
    @{ Label = "in-scope URL"; CommandLine = "curl https://api.example.org/x"; Expected = "allow" },
    @{ Label = "out-of-scope URL"; CommandLine = "curl https://evil.test.org/x"; Expected = "force_ask" },
    @{ Label = "lab private IP"; CommandLine = "Test-Connection -ComputerName 10.0.0.5"; Expected = "allow" },
    @{ Label = "lab wildcard"; CommandLine = "curl http://airways.htb/"; Expected = "allow" },
    @{ Label = "noise reference"; CommandLine = "curl https://medium.com/@x/y"; Expected = "allow" },
    @{ Label = "destructive"; CommandLine = "rm -rf /"; Expected = "deny" }
)

$failures = 0
foreach ($case in $cases) {
    $body = @{
        toolCall = @{
            name = "run_command"
            args = @{ CommandLine = $case.CommandLine }
        }
    } | ConvertTo-Json -Depth 6 -Compress
    $result = $body | & $python $gate
    $decision = ($result | ConvertFrom-Json).decision
    $ok = $decision -eq $case.Expected
    if (-not $ok) { $failures++ }
    "{0,-20} {1,-10} {2,-10} {3}" -f $case.Label, $case.Expected, $decision, $(if ($ok) { "ok" } else { "FAIL" })
}

if ($failures) {
    "FAILED: {0} of {1} cases" -f $failures, $cases.Count
    exit 1
}
"OK: {0}/{0} cases" -f $cases.Count
