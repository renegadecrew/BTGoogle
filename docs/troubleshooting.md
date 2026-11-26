# Troubleshooting

## The hook never fires

Check the location first. Hooks in `~/.gemini/antigravity-cli/settings.json`
are not loaded. Use one of:

- `.agents/hooks.json` in the workspace
- `~/.gemini/config/hooks.json`

Then confirm the entry is enabled and the matcher matches the tool name you
are testing. In the TUI, `/hooks` lists the hooks that are loaded.

## Every command prompts

The gate is finding an out-of-scope target. Read the `reason` field: it names
the host.

- If the host is a real target, add it to a program.
- If the host is a reference, add it to `noise.json`.

Do not switch the decision to `allow`. That removes the control instead of
fixing the data.

## The gate prompts on code, file names, or lab IPs

Confirm you are running this implementation, not an older one that scanned all
text with a domain regex. The test matrix in `tests/test_gate.py` includes
exactly these cases and should pass.

## `noise.json` changes have no effect

Check the encoding. A UTF-8 BOM at the start of the file makes `json.load`
fail, and the loader falls back to its built-in list silently.

The loader opens the file with `utf-8-sig`, which tolerates a BOM. If you edit
the file with a tool that writes a BOM, keep that encoding.

To verify:

```powershell
$bytes = [System.IO.File]::ReadAllBytes("$env:USERPROFILE\.gemini\config\hooks\noise.json")
"BOM: $($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)"
```

## The gate answers `allow` with `reason: invalid JSON payload`

Your shell reached the gate but the JSON did not parse, so the gate failed
open. The usual cause on Windows is Windows PowerShell 5.1, which encodes
strings piped into a native command as UTF-8 *with* a BOM:

```powershell
Get-Content tests/payloads/deny-destructive.json -Raw | python hooks\scope_gate.py
```

The gate strips a BOM from stdin, so this works on current builds. On an older
copy, the same command returns `allow` for `rm -rf /`. Set the encoding before
piping, or use `powershell -File scripts/verify.ps1`, which now fails when a
decision differs from the expected one instead of only printing it.

## Every out-of-scope host prompts, even ones you approved

That is `force_ask` working as designed: it ignores cached Always-Allow, so a
target outside the contract is never approved by muscle memory.

To respect Always-Allow instead:

```powershell
setx BTG_OUT_OF_SCOPE ask
```

The trade-off: a cached approval can now cover an out-of-scope host.

## Private lab addresses prompt

By default they are skipped and never prompt. If they prompt, private gating
is enabled:

```powershell
setx BTG_GATE_PRIVATE_IPS 1
```

Either disable it, or keep `lab.md` in the programs directory so the RFC 1918
ranges are explicitly authorized.

## `.htb` hostnames are not authorized

Single-label wildcards such as `*.htb` are accepted only for the lab TLDs
listed in `LAB_TLDS` (`htb`, `local`, `lab`, `test`, `internal`). A wildcard
such as `*.com` is rejected by design. Put lab hostnames in `lab.md`:

```markdown
## In-scope
*.htb
*.local
```

## The log

Every decision is appended to `~/.gemini/config/.hook_state/scope-gate.log`
as JSON Lines. Override the path with `BTG_LOG_FILE`.

Useful queries:

```powershell
Get-Content "$env:USERPROFILE\.gemini\config\.hook_state\scope-gate.log" -Tail 20
```

The log rotates to `.log.1` at 2 MB.
