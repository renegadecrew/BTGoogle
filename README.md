# BTGoogle

**Blue-team scope enforcement for Google Antigravity tool hooks.**

An agent that can run commands, fetch URLs, and write files is only as safe as
the boundary you put around it. BTGoogle is a `PreToolUse` hook that enforces a
file-based scope registry and refuses to turn every dotted identifier, file
name, or private lab address into a security prompt.

- No hidden state: authorization lives in Markdown files you can review.
- No network calls: the gate is pure text matching.
- No silent widening: out-of-scope hosts prompt; explicit exclusions always win.
- Fail-open: a crashing gate logs the error and allows, instead of bricking the
  agent.

```
   agent tool call
          |
          v
   +--------------+     no network context      +---------+
   | PreToolUse   | --------------------------> |  allow  |
   |  scope gate  |                             +---------+
   +--------------+
          |  URL / network tool / host flag
          v
   +--------------+     file name, noise,      +---------+
   |  extract     | --- private address ------> |  allow  |
   |  targets     |                             +---------+
   +--------------+
          |
          v
   +--------------+     authorized by a        +---------+
   |  match vs    | --- program file --------> |  allow  |
   |  programs/   |                             +---------+
   +--------------+
          |  no program authorizes it
          v
   +--------------+
   |  force_ask   |
   +--------------+
```

## Why

A scope gate that flags `json.loads` as a domain, `release-2.ovpn` as a host,
and `10.0.0.5` as an out-of-scope target is not a safety control. It is noise.
Operators learn to approve every prompt, and the one prompt that mattered is
approved with the rest.

The fix is precision, not permissiveness:

1. Extract targets only from contexts where a network target exists.
2. Keep authorization in an explicit, reviewable registry.
3. Never learn scope from the agent's own traffic. An auto-scope that
   authorizes whatever the agent touches is indistinguishable from no gate.

## Repository layout

```
BTGoogle/
├── hooks/
│   ├── scope_gate.py          # the PreToolUse hook
│   ├── noise.json             # reference domains that are never targets
│   ├── hooks.json.example     # Antigravity hook configuration
│   └── programs/
│       ├── example-program.md # template: replace with your engagement
│       └── lab.md             # RFC 1918 ranges and lab wildcards
├── tests/
│   └── test_gate.py           # replication matrix (18 cases)
├── scripts/
│   ├── install.ps1            # copy into ~/.gemini/config
│   └── verify.ps1             # send sample payloads through the gate
└── docs/
    ├── hook-contract.md       # Antigravity hook schema
    ├── scope-model.md         # program files, matching, precedence
    ├── target-extraction.md   # inspected and ignored contexts
    └── troubleshooting.md
```

## Quickstart

Requirements: Python 3.9 or newer, PowerShell 7 (or Windows PowerShell 5.1),
and Google Antigravity with hooks enabled.

### 1. Clone and test

```powershell
git clone <your-fork-url> BTGoogle
Set-Location BTGoogle
python tests/test_gate.py
```

Expected output:

```
18/18 passed
```

### 2. Install

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install.ps1
```

The script copies `scope_gate.py` and `noise.json` into
`%USERPROFILE%\.gemini\config\hooks\`, copies the example programs into
`%USERPROFILE%\.gemini\config\engagements\programs\` when they do not already
exist, and prints the `hooks.json` entry to add. It backs up existing files and
never overwrites `hooks.json`.

### 3. Register the hook

Merge the printed entry into `%USERPROFILE%\.gemini\config\hooks.json`:

```json
{
  "scope-gate": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "run_command|manage_task|read_url_content|search_web|ask_permission|write_to_file|replace_file_content|multi_replace_file_content|browser_.*",
        "hooks": [
          {
            "type": "command",
            "command": "python C:/Users/<you>/.gemini/config/hooks/scope_gate.py",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

Use forward slashes in `command`. Restart Antigravity or reload hooks, then
confirm with `/hooks` in the TUI.

### 4. Add your real scope

Replace `hooks/programs/example-program.md` with your engagement:

```markdown
# Program: acme
expires: 2027-03-31

## In-scope

*.acme.example
acme.example
203.0.113.0/24

## Out-of-scope

legacy.acme.example
```

### 5. Verify

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
```

## Configuration

All configuration is through environment variables and files.

| Variable | Default | Purpose |
|---|---|---|
| `BTG_PROGRAMS_DIR` | `~/.gemini/config/engagements/programs` | Directory of `*.md` programs |
| `BTG_NOISE_FILE` | `~/.gemini/config/hooks/noise.json` | Reference-domain list |
| `BTG_LOG_FILE` | `~/.gemini/config/.hook_state/scope-gate.log` | JSON Lines decision log |
| `BTG_OUT_OF_SCOPE` | `force_ask` | `force_ask` (always prompt) or `ask` (respect Always-Allow) |
| `BTG_GATE_PRIVATE_IPS` | unset | `1` also gates private/loopback/link-local addresses |

Only `force_ask` and `ask` are accepted for `BTG_OUT_OF_SCOPE`. The value is
validated so a typo cannot turn the gate into `allow`.

## Decision log

Every decision is appended as JSON Lines:

```json
{"event": "allow", "tool": "run_command", "targets": ["example.com"], "ts": "2026-01-01T00:00:00+00:00"}
{"event": "ask", "problems": ["example.net is not covered by any program"], "text": "curl https://example.net/", "ts": "..."}
```

The file rotates to `.log.1` at 2 MB.

## Design notes

**Context-aware extraction.** The gate inspects URLs, arguments to known
network tools, and host flags. It ignores search queries without URLs, code
identifiers, and file names. See `docs/target-extraction.md`.

**Explicit registry.** Authorization is derived from Markdown files that a
reviewer can read and diff. There is no database and no learned state. See
`docs/scope-model.md`.

**Exclusion precedence.** An explicit out-of-scope asset removes a host even
when a wildcard covers it.

**Persistence guard.** Writes to hook configuration, git hooks, shell profiles,
and agent credential files return `force_ask`, regardless of scope. Those paths
are how a single fetched page becomes code execution on every future tool call.

**Fail-open.** A crashing hook returns `allow` and logs the error. A gate that
blocks everything gets disabled in a day.

## Limitations

- The gate sees the agent's command text, not the behavior of the programs it
  runs. A binary that beacons to a command-and-control server is outside the
  gate's visibility. Isolate untrusted binaries at the network layer.
- Matching is textual. No DNS resolution, no certificate validation, and no
  ownership verification.
- Scope is not inferred from conversation history. Programs are added
  explicitly.
- The standalone gate does not include transcript auto-capture. Add programs
  with `scope_add.py` or by writing a Markdown file.

## Further reading

- Antigravity hooks: <https://antigravity.google/docs/hooks>
- Antigravity permissions and sandbox: <https://antigravity.google/docs/permissions/>
- Antigravity browser allowlist and denylist:
  <https://antigravity.google/docs/ide/allowlist-denylist/>

## License

MIT. See `LICENSE`.
