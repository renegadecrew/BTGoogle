# Threat model

BTGoogle is a `PreToolUse` gate. It is a **speed bump with an audit trail**, not
a sandbox. This page states exactly what it stops, what it does not, and which
assumptions the operator has to keep true.

## Trust boundary

The gate runs as a child process of Antigravity, reads a JSON payload from
stdin, and writes a decision to stdout. It trusts:

- the **payload** Antigravity sends (`toolCall.name`, `toolCall.args`,
  `transcriptPath`, `conversationId`);
- the **program files** under `~/.gemini/config/engagements/programs/`;
- the **noise list** at `~/.gemini/config/hooks/noise.json`.

It does **not** trust the agent's command text. The agent is the thing being
bounded, so every host, flag, and path in that text is treated as hostile until
the registry authorizes it.

The registry itself is trusted **only if the agent cannot write it**. That is
why `engagements/` and `brain/*/.system_generated/` are hard-deny paths.

## What the gate enforces

| Rule | Decision | Why |
|---|---|---|
| Network target not covered by a program | `force_ask` | The operator decides whether the engagement covers it |
| Network target explicitly out of scope | `force_ask` | An exclusion always wins over a wildcard |
| Recursive delete of `/`, `~`, `$HOME`, a drive root | `deny` | No undo, no small blast radius |
| Raw disk write, `mkfs`, volume format, fork bomb, `DROP TABLE` | `deny` | Same |
| Forced `git push` | `force_ask` | Rewrites shared history |
| Write to hook config, git hooks, shell rc, credential files | `force_ask` | Persistence: one write becomes code execution later |
| Write to the scope registry or the transcript/task logs | `deny` | Self-authorization: the agent would write its own permission |
| Empty registry | `force_ask` | A gate with no rules must not be a no-op |
| Gate crash / invalid JSON | `allow` (default) or `force_ask` with `BTG_FAIL_CLOSED=1` | Configurable tradeoff |

## What it does not do

- **It is not an OS sandbox.** A binary the agent runs can open sockets, read
  files, and beacon out. The gate sees the command line, not the process.
  Isolate untrusted binaries at the network/VM layer.
- **It does not resolve DNS or verify ownership.** Matching is textual against
  the program files.
- **It does not inspect every encoding.** `powershell -enc` is decoded;
  arbitrary base64 in another language, a compiled payload, or a here-doc that
  builds a URL at runtime is outside the parser.
- **It does not judge the destination of every tool.** It judges URLs, known
  network tools, host flags, SSH destinations/jumps/forwards, and URL-named
  arguments on unknown tools. A plugin with a custom argument name needs
  `TARGET_TEXT_TOOLS` extended.
- **It does not stop a human-approved action.** `force_ask` is a prompt. If the
  operator clicks through, the action proceeds; that is the design.

## Attack chains that are closed

1. **Registry write.** `write_to_file` to
   `~/.gemini/config/engagements/programs/evil.md` used to return `allow`; the
   agent could add its own scope and then scan anything. Now `deny`.
2. **Transcript write + auto-capture.** The transcript lives under
   `brain/<id>/.system_generated/logs/`. Writing a fake `USER_INPUT` line and
   letting `auto_capture` read it authorized the target. Now transcript writes
   are `deny`, and auto-capture is off unless `BTG_AUTO_CAPTURE=1`.
3. **Empty registry.** A fresh install with no programs allowed everything.
   Now it returns `force_ask`, and the installer copies the example programs
   (only if missing).
4. **Equivalent destructive syntax.** `rm -r -f /`,
   `rm --recursive --force /`, `rm -rf "$HOME"`, `rm -rf "${HOME}"`,
   `rm -rf -- /`, and `rd /q /s C:\` used to return `allow`. The gate now
   normalizes each command segment with `shlex` and judges the argv.
5. **Hosts hidden in SSH options.** `ssh -J evil.test.org target`,
   `ssh -o ProxyJump=evil.test.org target`, and
   `ssh -L 8080:evil.test.org:80 target` used to return `allow`. The SSH
   parser now reads `-J`, `ProxyJump`, `ProxyCommand`, and `-L/-R/-D` values.

## Failure modes

- **Fail-open.** A bug in the gate returns `allow` and logs the error, so the
  agent keeps working. This is a deliberate availability tradeoff. Set
  `BTG_FAIL_CLOSED=1` if a wrong `allow` is worse than a broken agent.
- **Empty registry.** Returns `force_ask`; `BTG_ALLOW_EMPTY=1` is the explicit
  escape hatch.
- **Log growth.** The log rotates to `.log.1` at 2 MB.
- **Secrets in logs.** Commands are redacted before they are written: bearer
  tokens, `token=`, `password=`, `--password`, `-u user:pass`, and URL
  userinfo. Redaction is best-effort; do not put secrets on a command line.

## Operator checklist

1. Keep `~/.gemini/config/engagements/` and `~/.gemini/antigravity/brain/`
   writable only by you, not by the agent's tools.
2. Add scope with `scope_add.py` or a reviewed Markdown file. Do not enable
   `BTG_AUTO_CAPTURE` unless you accept that a writable transcript can become
   an authorization.
3. Keep `noise.json` short and explicit. Every entry is a host the gate stops
   judging.
4. Run `python scripts/pin_hook.py --check` after upgrading; it runs the
   behavior matrix against the installed file, not just the hash.
5. Treat `force_ask` as a real decision. Clicking through is the operator's
   authorization, not the gate's.
