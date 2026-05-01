# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A bundle of hardened hooks and a permission policy template for Claude Code itself. Everything is plain Python 3.9+ (stdlib only) and a single bash installer. There is no build step, no package manager, and no runtime dependencies.

## Common commands

```bash
./install.sh        # copies hooks/*.py into ~/.claude/hooks/ and offers to install templates/settings.json
./tests/run.sh      # smoke tests — pipes JSON payloads to each hook, asserts exit codes / stdout
```

There is no single-test runner; `tests/run.sh` is a flat shell script. To exercise a single hook, run it directly:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | hooks/bash-guard.py
```

## Architecture

The four hooks form a layered policy. Each is independent, reads one JSON object from stdin, and signals decisions via the contract Claude Code expects for that hook event:

- [hooks/bash-guard.py](hooks/bash-guard.py) — `PreToolUse:Bash`. Regex-scans the **raw command string** for dangerous patterns regardless of position (chains, `timeout` wrappers, `docker exec` env-runners, subshells). Block = `exit 2`. The PATTERNS list at the top is the policy surface.
- [hooks/edit-write-guard.py](hooks/edit-write-guard.py) — `PreToolUse:Edit|Write`. Two checks: `PATH_DENY` (regex on `file_path`) and `CONTENT_DENY` (regex on `content` / `new_string` for credential shapes). Block = JSON `permissionDecision: "deny"` on stdout (not `exit 2` — see #13744).
- [hooks/audit.py](hooks/audit.py) — `PostToolUse`. Always exits 0; never blocks. Appends one JSON line per tool call to `~/.claude/session-logs/YYYY-MM-DD.jsonl`.
- [hooks/session-start.py](hooks/session-start.py) — `SessionStart`. Refuses to start (exit 2) when project-local `.claude/settings.json` contains red flags (`ANTHROPIC_BASE_URL`, `enableAllProjectMcpServers`, hook commands containing `curl`/`wget`/`bash -c`/command substitution).

[templates/settings.json](templates/settings.json) wires the four hooks into the matching events and ships the matching `permissions.allow / deny / ask` lists. The permissions are belt-and-braces — the README's threat-surface notes explain that prefix-matching alone is insufficient (chains and wrappers bypass it), which is why the bash hook re-evaluates the whole command string instead of relying on permission patterns.

## Editing the policy

Each hook keeps its policy as a list literal at the top of the file (`PATTERNS`, `PATH_DENY`, `CONTENT_DENY`). Modify those, then add a corresponding case to [tests/run.sh](tests/run.sh) — it asserts blocking/allow behavior with `run_bash`, `run_editwrite_block`, `run_editwrite_allow`, and `run_passthrough` helpers. Real-world credentials must never appear in test fixtures; the script already splits them across string concatenations (`AWS_KEY="AKI""AIOSFODNN7EXAMPLE"`) so `tests/run.sh` itself doesn't trip the content scanner when authored through Claude Code.

The hooks are intentionally short and stdlib-only — keep them that way.

## Hook I/O contract reminders

- Bash hook: block via `exit 2` + stderr message. Claude Code surfaces stderr to the model.
- Edit/Write hook: block via JSON `{hookSpecificOutput: {hookEventName, permissionDecision: "deny", permissionDecisionReason}}` on stdout, then `exit 0`. `exit 2` is unreliable for these tools.
- Audit hook: never block. Wrap I/O in try/except and exit 0 even on parse failure.
- SessionStart hook: red-flag detection is a substring/JSON-walk on the project's `.claude/settings.json` and `.claude/settings.local.json`; this is the post-CVE-2025-59536 hygiene check.
