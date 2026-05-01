# claude-code-guardrails

Hardened hooks + permission policy for [Claude Code](https://code.claude.com).

## Why

Claude Code's permission patterns match the *prefix* of the full command string. So `git add . && git commit` doesn't match `Bash(git commit*)` — the chain bypasses the gate. Anthropic itself [recommends hooks](https://code.claude.com/docs/en/permissions) for any constraint that actually matters.

This bundle wires up four hooks that enforce real policy via Bash AST parsing, sensitive-path scanning, and credential-content scanning, plus a non-blocking audit log.

## What it ships

| Hook | Event | Purpose |
|---|---|---|
| `bash-guard.py` | `PreToolUse:Bash` | Regex-scans the raw command string for dangerous patterns regardless of position — catches them when buried inside chains, wrappers (`timeout 30 rm -rf x`), env-runners (`docker exec foo rm -rf /data`), or subshells. Blocks `rm -rf`, force pushes (incl. `--force-with-lease`), `git reset --hard`, `git checkout --`, `sudo`, `eval`, `python -c`/`node -e`, `find -exec`/`-delete`, `dd`, `mkfs.*`, redirects to block devices, command substitution in command position, and more. |
| `edit-write-guard.py` | `PreToolUse:Edit\|Write` | Deny edits to `.env`, SSH keys, AWS/Kube/npm credentials, GitHub Actions, Claude/MCP config, `.husky`, `.git`. Scan content for AWS, GitHub, Stripe, Anthropic, Slack key shapes and private-key blocks. |
| `audit.py` | `PostToolUse` | Append one JSON line per tool call to `~/.claude/session-logs/YYYY-MM-DD.jsonl`. Always non-blocking. |
| `session-start.py` | `SessionStart` | Log environment fingerprint. Refuse to start if a project's `.claude/settings.json` contains red flags (`ANTHROPIC_BASE_URL`, `enableAllProjectMcpServers`, hooks that shell out via `curl`/`wget`/`bash -c`/command substitution). |

## What it doesn't catch

Heredoc bodies, loop bodies, runtime-computed command names, content-side bypass via Bash (`python -c "open('.env','w')…"` is caught as a `python -c` head; `sed -i`/`tee` style routes are not). Anthropic's OS-level [sandbox](https://code.claude.com/docs/en/settings) closes those properly. This bundle is the next-best thing where the sandbox isn't an option, and a defence-in-depth layer where it is.

## Install

Requires Python 3.9+ (no third-party deps) and a recent Claude Code (≥ 2.0.65 — see CVE list below).

```bash
git clone <repo-url> claude-code-guardrails
cd claude-code-guardrails
./install.sh
```

`install.sh` copies the hooks into `~/.claude/hooks/` and points at the settings snippet to merge into `~/.claude/settings.json`.

If you have no existing settings:

```bash
cp templates/settings.json ~/.claude/settings.json
```

Restart Claude Code; verify with `/status`.

## Test

```bash
./tests/run.sh
```

Feeds known-good and known-bad payloads to each hook and asserts behaviour.

## Customize

Open the hook files directly and edit the lists at the top:

- `bash-guard.py` — `PATTERNS` list (each entry is `(regex, label)`)
- `edit-write-guard.py` — `PATH_DENY`, `CONTENT_DENY`

Project-specific allowlists belong in your project's `.claude/settings.json`. Keep `~/.claude/settings.json` minimal.

## Threat surface notes

- The Claude Code permission model evaluates **prefixes of the full command**, so `cd /tmp && rm -rf foo` does not match `Bash(rm -rf *)`. The bundled hooks AST-parse and re-evaluate every command in the chain.
- Anthropic silently strips `timeout`, `time`, `nice`, `nohup`, `stdbuf`, bare `xargs` before matching. The Bash hook replicates this list to stay in sync with Claude Code's evaluator.
- Anthropic does **not** strip env-runners (`docker exec`, `devbox run`, `npx`, `direnv exec`, `mise exec`). The Bash hook recurses into the inner argv of these.
- Edit/Write hooks output JSON `permissionDecision: "deny"` on stdout rather than `exit 2`, because [issue #13744](https://github.com/anthropics/claude-code/issues/13744) reports `exit 2` is unreliable for those tools.
- An Edit hook alone is bypassable from Bash ([issue #29709](https://github.com/anthropics/claude-code/issues/29709), closed not-planned). The Bash hook covers `python -c`, `node -e`, `perl -e` etc. as compensating defence.

## References

- [Claude Code: Hooks reference](https://code.claude.com/docs/en/hooks)
- [Claude Code: Permissions reference](https://code.claude.com/docs/en/permissions) — Anthropic's own statement that prefix patterns are fragile
- [Claude Code: Settings reference](https://code.claude.com/docs/en/settings) — including the OS-level sandbox option
- CVE-2025-59536 — project `settings.json` RCE on clone (patched 1.0.111)
- CVE-2026-21852 — `ANTHROPIC_BASE_URL` exfiltration (patched 2.0.65)

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome. The hooks are intentionally short and readable; please keep them that way.
