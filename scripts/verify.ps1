<#
.SYNOPSIS
    Send representative PreToolUse payloads through the installed gate.

.DESCRIPTION
    Reads hooks/scope_gate_v2.py from this repository (the pinned gate) and
    prints the decision for a set of commands, failing when a decision differs
    from the expected one. It does not touch the live Antigravity configuration.

.NOTES
    Run from the repository root:

        powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
#>

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$gate = Join-Path $repo "hooks\scope_gate_v2.py"
$python = (Get-Command python -ErrorAction Stop).Source

# Deliberately no $OutputEncoding override: Windows PowerShell 5.1 pipes UTF-8
# with a BOM, PowerShell 7 pipes it without, and this script should exercise
# whichever one the caller shell really does. The gate strips a BOM from stdin,
# so the decisions must come out the same either way.

$state = Join-Path $env:TEMP "btg-verify-state"
New-Item -ItemType Directory -Force -Path $state | Out-Null

$env:ANTIGRAVITY_ENGAGEMENTS_DIR = Join-Path $repo "hooks\programs"
$env:ANTIGRAVITY_GATE_NOISE = Join-Path $repo "hooks\noise.json"
$env:ANTIGRAVITY_STATE_DIR = $state
$env:BTG_LOG_FILE = Join-Path $env:TEMP "btg-verify.log"
foreach ($knob in @("BTG_AUTO_CAPTURE", "BTG_ALLOW_ANY_TRANSCRIPT",
                    "BTG_ALLOW_EMPTY", "BTG_FAIL_CLOSED",
                    "BTG_GATE_PRIVATE_IPS", "ANTIGRAVITY_GATE_PRIVATE_IPS",
                    "ANTIGRAVITY_SCOPE_FILE")) {
    Remove-Item "Env:$knob" -ErrorAction SilentlyContinue
}

$homeDir = $env:USERPROFILE
$registryWrite = [System.IO.Path]::Combine(
    $homeDir, ".gemini", "config", "engagements", "programs", "evil.md")
$transcriptWrite = [System.IO.Path]::Combine(
    $homeDir, ".gemini", "antigravity", "brain", "conv-1",
    ".system_generated", "logs", "transcript_full.jsonl")

$cases = @(
    @{ Label = "python identifier"; CommandLine = 'python -c "import json; json.loads(s)"'; Expected = "allow" },
    @{ Label = "in-scope URL"; CommandLine = "curl https://api.example.org/x"; Expected = "allow" },
    @{ Label = "out-of-scope URL"; CommandLine = "curl https://evil.test.org/x"; Expected = "force_ask" },
    @{ Label = "lab private IP"; CommandLine = "Test-Connection -ComputerName 10.0.0.5"; Expected = "allow" },
    @{ Label = "lab wildcard"; CommandLine = "curl http://airways.htb/"; Expected = "allow" },
    @{ Label = "noise reference"; CommandLine = "curl https://medium.com/@x/y"; Expected = "allow" },
    @{ Label = "destructive"; CommandLine = "rm -rf /"; Expected = "deny" },
    @{ Label = "rm split flags"; CommandLine = "rm -r -f /"; Expected = "deny" },
    @{ Label = "rm long flags"; CommandLine = "rm --recursive --force /"; Expected = "deny" },
    @{ Label = "rm quoted HOME"; CommandLine = 'rm -rf "$HOME"'; Expected = "deny" },
    @{ Label = "rm double dash"; CommandLine = "rm -rf -- /"; Expected = "deny" },
    @{ Label = "rd drive root"; CommandLine = "rd /q /s C:\"; Expected = "deny" },
    @{ Label = "ssh jump host"; CommandLine = "ssh -J evil.test.org target"; Expected = "force_ask" },
    @{ Label = "ssh local forward"; CommandLine = "ssh -L 8080:evil.test.org:80 target"; Expected = "force_ask" },
    @{ Label = "ftp URL"; CommandLine = "curl ftp://evil.test.org/x"; Expected = "force_ask" },
    @{ Label = "registry write"; Tool = "write_to_file"; Field = "TargetFile"; Value = $registryWrite; Expected = "deny" },
    @{ Label = "transcript write"; Tool = "write_to_file"; Field = "TargetFile"; Value = $transcriptWrite; Expected = "deny" }
)

$failures = 0
foreach ($case in $cases) {
    $tool = if ($case.ContainsKey("Tool")) { $case.Tool } else { "run_command" }
    $field = if ($case.ContainsKey("Field")) { $case.Field } else { "CommandLine" }
    $value = if ($case.ContainsKey("Value")) { $case.Value } else { $case.CommandLine }
    $body = @{
        toolCall = @{
            name = $tool
            args = @{ $field = $value }
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
