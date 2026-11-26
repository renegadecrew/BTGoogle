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
  "transcriptPath": "~/.gemini/antigravity/brain/<id>/.system_generated/logs/transcript.jsonl",
  "artifactDirectoryPath": "~/.gemini/antigravity/brain/<id>",
  "modelName": "gemini-3.6-flash-medium"
}
```

The fields this gate reads are `toolCall.name` and `toolCall.args`.

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
`TARGET_TEXT_TOOLS` in the installed gate (`hooks/scope_gate_v2.py`) — or
`TEXT_TOOLS` in the dependency-free reference gate (`hooks/scope_gate.py`) — and
the matcher together.

## Forced pushes

`git push --force` and `-f` return `force_ask`; `--force-with-lease` and
`--force-if-includes` are the careful forms and pass. Remote history has no clean
undo and a forced push is rare, so the prompt costs nothing. Nothing else about
git is judged by the gate — that is what human review is for.

## Fail-open behavior

If the hook crashes or receives invalid JSON, it returns `allow` and writes the
error to the log. A gate that crashes and blocks every call makes the agent
unusable, which pushes operators to disable it entirely. Failing open keeps the
control in place while surfacing the defect in the log.
