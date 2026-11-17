<#
.SYNOPSIS
    Install the BTGoogle scope gate into a Google Antigravity configuration.

.DESCRIPTION
    Copies the gate, the noise list, and the example programs into the global
    Antigravity configuration directory. Existing files are backed up first.
    The hooks.json entry is printed but never overwritten automatically.

.NOTES
    Run from the repository root:

        powershell -ExecutionPolicy Bypass -File scripts/install.ps1
#>

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$config = Join-Path $env:USERPROFILE ".gemini\config"
$hooksDir = Join-Path $config "hooks"
$programsDir = Join-Path $config "engagements\programs"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

foreach ($dir in @($hooksDir, $programsDir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

function Install-File {
    param([string]$Source, [string]$Destination)
    if (Test-Path -LiteralPath $Destination) {
        $backup = "$Destination.bak-$stamp"
        Copy-Item -LiteralPath $Destination -Destination $backup -Force
        Write-Host "backup  $backup"
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    Write-Host "install $Destination"
}

Install-File (Join-Path $repo "hooks\scope_gate.py") (Join-Path $hooksDir "scope_gate.py")
Install-File (Join-Path $repo "hooks\noise.json") (Join-Path $hooksDir "noise.json")

Get-ChildItem -LiteralPath (Join-Path $repo "hooks\programs") -Filter *.md | ForEach-Object {
    $destination = Join-Path $programsDir $_.Name
    if (-not (Test-Path -LiteralPath $destination)) {
        Copy-Item -LiteralPath $_.FullName -Destination $destination
        Write-Host "install $destination"
    } else {
        Write-Host "skip    $destination (already exists)"
    }
}

$hookCommand = "python " + ((Join-Path $hooksDir "scope_gate.py") -replace "\\", "/")
$snippet = @"
Add this entry to $config\hooks.json (merge with existing entries, do not replace the file):

  "scope-gate": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "run_command|manage_task|read_url_content|search_web|ask_permission|write_to_file|replace_file_content|multi_replace_file_content|browser_.*",
        "hooks": [
          { "type": "command", "command": "$hookCommand", "timeout": 15 }
        ]
      }
    ]
  }
"@
Write-Host ""
Write-Host $snippet
