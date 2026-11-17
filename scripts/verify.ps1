<#
.SYNOPSIS
    Send representative PreToolUse payloads through the installed gate.

.DESCRIPTION
    Reads hooks/scope_gate.py from this repository and prints the decision for
    a set of commands. It does not touch the live Antigravity configuration.

.NOTES
    Run from the repository root:

        powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
#>

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$gate = Join-Path $repo "hooks\scope_gate.py"
$python = (Get-Command python -ErrorAction Stop).Source

$env:BTG_PROGRAMS_DIR = Join-Path $repo "hooks\programs"
$env:BTG_NOISE_FILE = Join-Path $repo "hooks\noise.json"
$env:BTG_LOG_FILE = Join-Path $env:TEMP "btg-verify.log"

$cases = @(
    @{ Label = "python identifier"; CommandLine = 'python -c "import json; json.loads(s)"' },
    @{ Label = "in-scope URL"; CommandLine = "curl https://api.example.org/x" },
    @{ Label = "out-of-scope URL"; CommandLine = "curl https://evil.test.org/x" },
    @{ Label = "lab private IP"; CommandLine = "Test-Connection -ComputerName 10.0.0.5" },
    @{ Label = "lab wildcard"; CommandLine = "curl http://airways.htb/" },
    @{ Label = "noise reference"; CommandLine = "curl https://medium.com/@x/y" },
    @{ Label = "destructive"; CommandLine = "rm -rf /" }
)

foreach ($case in $cases) {
    $body = @{
        toolCall = @{
            name = "run_command"
            args = @{ CommandLine = $case.CommandLine }
        }
    } | ConvertTo-Json -Depth 6 -Compress
    $result = $body | & $python $gate
    "{0,-20} -> {1}" -f $case.Label, $result
}
