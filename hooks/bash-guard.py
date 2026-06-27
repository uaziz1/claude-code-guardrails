#!/usr/bin/env python3
"""Bash command guard for Claude Code PreToolUse:Bash.

Substring-scans the raw command for dangerous patterns regardless of where
they appear in the command string. This deliberately catches dangerous
operations even when buried inside:

- chains:        a && b ; c | d
- wrappers:      timeout 30 rm -rf x   (no need to know timeout's arg shape)
- env-runners:   docker exec foo rm -rf /data
- subshells:     ( cd /tmp && rm -rf x )

A regex on the full command string is the right tool here: the threat is
the dangerous text appearing anywhere, and trying to AST-parse it just
shifts complexity for no security gain (and is itself bypassable via
heredoc bodies, runtime-computed names, etc.).
"""
import json, re, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mode import current_mode  # noqa: E402


# Roots where bash writes are pre-approved without prompting. Project CWD
# is always allowed; this list extends it with transient/cache locations.
# Anything outside both gets `ask` (PrincipleOfLeastPrivilege at the boundary).
# Edit this list — or set CCG_WRITE_ALLOW_ROOTS — to pre-approve more.
_HOME = os.path.expanduser("~")
WRITE_ALLOW_ROOTS = [r for r in (
    "/tmp", "/private/tmp", "/var/tmp",
    os.environ.get("TMPDIR", "").rstrip("/") or None,
    os.path.join(_HOME, ".cache"),
    os.path.join(_HOME, "Library/Caches"),
) if r]
WRITE_ALLOW_ROOTS += [
    r.rstrip("/") for r in os.environ.get("CCG_WRITE_ALLOW_ROOTS", "").split(",") if r.strip()
]

# Pseudo-devices that are not real files: redirecting to them (e.g. the
# ubiquitous `2>/dev/null`) is never a filesystem write and must not trip the
# write-scope check. Actual block-device writes (/dev/sd*, /dev/nvme*, …) are
# caught separately by the catastrophic "redirect to block device" rule.
ALWAYS_OK_WRITE = {
    "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero", "/dev/fd",
}


# Roots whose contents are credential-shaped but the agent legitimately reads
# from them (e.g. `~/.cyrus/` holds Cyrus's `.env`-shaped credentials file).
# These are exempted from the SENSITIVE_PATH scan ONLY — `rm -rf`, pipe-to-
# shell, etc. still apply if the command happens to touch one of these paths.
# Override with comma-separated CCG_BASH_SENSITIVE_EXEMPT.
SENSITIVE_EXEMPT_ROOTS = [
    p.rstrip("/") for p in os.environ.get(
        "CCG_BASH_SENSITIVE_EXEMPT", "~/.cyrus"
    ).split(",") if p.strip()
]


def _strip_exempt_paths(cmd):
    """Replace exempt-root path tokens with a placeholder for the
    SENSITIVE_PATH scan. The match stops at shell metacharacters so chained
    commands (`; | & < > ( ) backtick $`) and quotes don't get swallowed —
    otherwise greedy non-whitespace would consume `;rm -rf /` and bypass
    the destructive-command rules.
    """
    out = cmd
    for root in SENSITIVE_EXEMPT_ROOTS:
        # Match both ~ form and absolute form.
        for r in {root, os.path.expanduser(root)}:
            out = re.sub(
                re.escape(r) + r"(?:/[^\s;&|<>()'\"`$]*)?",
                "__exempt_path__",
                out,
            )
    return out


# Sensitive paths — secret-bearing tokens any read/write/move command might
# touch. Word-boundary-anchored so .env.example etc. is exempt.
# `@` is included so curl's `--data @file` / `--upload-file @file` forms,
# which read a file as the request body, can't quietly exfil secrets.
_LEAD = r"[\s/'\"=@]"
SENSITIVE_PATH = (
    r"(?:"
    rf"(?:^|{_LEAD})\.env\b(?!\.example|\.sample|\.template|\.dist)"
    rf"|(?:^|{_LEAD})\.(?:aws|ssh|kube|gnupg)/"
    rf"|(?:^|{_LEAD})\.netrc\b"
    rf"|(?:^|{_LEAD})\.npmrc\b"
    rf"|(?:^|{_LEAD})\.pypirc\b"
    r"|\bid_(?:rsa|ed25519|ecdsa|dsa)(?:\.pub)?\b"
    r")"
)


# Each entry is (pattern, label, tier). Tier "catastrophic" enforces in
# both modes; "strict" is dropped in build mode. Build mode keeps anything
# that destroys data irrecoverably, escalates privilege, exfils secrets,
# or formats devices, and drops things the agent legitimately needs while
# iterating (interpreter -c/-e, find -exec, command substitution, lower-
# blast-radius git ops, etc.).
PATTERNS = [
    # rm with both -r/-R and -f flags in any order
    (r"\brm\s+-[A-Za-z]*[rR][A-Za-z]*[fF]\b",
        "rm -rf (or -fr / -Rf / -fR variant)", "catastrophic"),
    (r"\brm\s+-[A-Za-z]*[fF][A-Za-z]*[rR]\b",
        "rm -fr (or -rf variant)", "catastrophic"),
    (r"\brm\s+(?:[^|;&]*?\s)?--recursive\b[^|;&]*?--force\b",
        "rm --recursive --force", "catastrophic"),
    (r"\brm\s+(?:[^|;&]*?\s)?--force\b[^|;&]*?--recursive\b",
        "rm --force --recursive", "catastrophic"),

    # git destructive operations
    (r"\bgit\s+push\s+[^|;&]*?(?:--force(?!-with-lease)|-f\b)",
        "git push --force", "catastrophic"),
    (r"\bgit\s+push\s+[^|;&]*?--force-with-lease\b",
        "git push --force-with-lease", "catastrophic"),
    # `git push origin +main` is force-push in disguise — `+refspec` syntax
    # is documented git for "allow non-fast-forward". Match a `+` token that
    # looks like a refspec arg (preceded by whitespace, not a flag).
    (r"\bgit\s+push\s+[^|;&]*?\s\+[A-Za-z0-9._/-]+(?::[A-Za-z0-9._/-]+)?(\s|$)",
        "git push +refspec (force in disguise)", "catastrophic"),
    (r"\bgit\s+reset\s+[^|;&]*?--hard\b",
        "git reset --hard", "catastrophic"),
    (r"\bgit\s+filter-branch\b",
        "git filter-branch", "catastrophic"),
    (r"\bgit\s+config\s+[^|;&]*?core\.hooksPath\b",
        "git config core.hooksPath", "catastrophic"),
    (r"\bgit\s+reflog\s+(?:expire|delete)\b",
        "git reflog expire/delete", "catastrophic"),
    (r"\bgit\s+clean\s+[^|;&]*?-[A-Za-z]*f",
        "git clean -f", "strict"),
    (r"\bgit\s+checkout\s+--(\s|$)",
        "git checkout --", "strict"),
    (r"\bgit\s+checkout\s+\.(\s|$)",
        "git checkout .", "strict"),
    (r"\bgit\s+restore\b",
        "git restore", "strict"),
    (r"\bgit\s+branch\s+[^|;&]*?-D\b",
        "git branch -D", "strict"),
    (r"\bgit\s+stash\s+(?:drop|clear)\b",
        "git stash drop/clear", "strict"),
    (r"\bgit\s+update-ref\s+[^|;&]*?-d\b",
        "git update-ref -d", "strict"),
    (r"\bgit\s+submodule\s+deinit\s+[^|;&]*?-f\b",
        "git submodule deinit -f", "strict"),
    (r"\bgit\s+gc\s+[^|;&]*?--prune\b",
        "git gc --prune", "strict"),

    # System / privilege escalation
    (r"\bsudo\b",                                  "sudo", "catastrophic"),
    (r"\bdoas\b",                                  "doas", "catastrophic"),
    (r"\bpkexec\b",                                "pkexec", "catastrophic"),
    (r"\beval\s",                                  "eval", "strict"),

    # Disk / filesystem destructive
    (r"\bdd\s+",                                   "dd", "catastrophic"),
    (r"\bmkfs\.",                                  "mkfs.* (format filesystem)", "catastrophic"),
    (r"\bshred\b",                                 "shred", "catastrophic"),
    (r"\bwipefs\b",                                "wipefs", "catastrophic"),
    (r">\s*/dev/(sd|nvme|disk[0-9]|hd|md)",        "redirect to block device", "catastrophic"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:",                 "fork bomb", "catastrophic"),

    # Network exfil / shell-from-stream
    (r"\b(?:curl|wget)\s+[^|;&]*?\|\s*(?:sh|bash|zsh|dash|ksh)\b",
        "curl|wget piped to shell", "catastrophic"),
    # curl/wget saving to an executable-looking path → high odds of
    # download-then-execute on the next command.
    (r"\b(?:curl|wget)\s+[^|;&]*?(?:-o|--output|-O)\s+\S+\.(?:sh|bash|zsh|py|rb|pl|exe|bat|ps1|cmd|scr|jar)\b",
        "curl|wget output to script/executable", "catastrophic"),
    (r"\bnc\s+(?:[^|;&]*?\s)?-l\b",                "nc -l (listener)", "catastrophic"),
    (r"\bnc\s+(?:[^|;&]*?\s)?-e\b",                "nc -e (command exec)", "catastrophic"),
    (r"\bsocat\b",                                 "socat", "catastrophic"),

    # Shell -c: arbitrary inline command. The most direct bypass otherwise.
    (r"\b(?:bash|zsh|fish|ksh|dash|sh)\s+(?:[^|;&]*?\s)?-c\b",
        "shell -c (bash/zsh/fish/ksh/dash/sh)", "strict"),

    # Interpreter -c / -e / -m: arbitrary code via Bash
    (r"\b(?:python|python3|python2)\s+(?:[^|;&]*?\s)?-c\b",
        "python -c", "strict"),
    (r"\b(?:python|python3|python2)\s+(?:[^|;&]*?\s)?-m\b",
        "python -m (arbitrary module exec)", "strict"),
    (r"\b(?:node|deno)\s+(?:[^|;&]*?\s)?(?:-e|--eval)\b",
        "node/deno -e", "strict"),
    (r"\bperl\s+(?:[^|;&]*?\s)?-e\b",
        "perl -e", "strict"),
    (r"\bruby\s+(?:[^|;&]*?\s)?-e\b",
        "ruby -e", "strict"),

    # find -exec / -delete: arbitrary command execution per match
    (r"\bfind\s+[^|;&]*?-(?:exec|execdir|delete)\b",
        "find -exec / -execdir / -delete", "strict"),

    # Command substitution in command position (rare in legit usage)
    (r"(?:^|[;&|]\s*)\$\(",                        "$( ... ) as command", "strict"),
    (r"(?:^|[;&|]\s*)`",                           "backtick substitution as command", "strict"),

    # Sensitive-path access. Catches reads (cat/head/less/sed/grep/xxd/base64/
    # tee), copies/renames (cp/mv/ln) and exfil (scp/rsync) of credentials,
    # which would otherwise bypass the Edit/Write hook entirely.
    (SENSITIVE_PATH, "command references sensitive path", "catastrophic"),
]


def ask(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def in_allow_root(path, cwd):
    """True if resolved `path` is inside `cwd` or any WRITE_ALLOW_ROOTS root."""
    if not path:
        return False
    try:
        p = os.path.realpath(path)
    except Exception:
        p = path
    for root in ([cwd] if cwd else []) + WRITE_ALLOW_ROOTS:
        if not root:
            continue
        try:
            r = os.path.realpath(root)
        except Exception:
            r = root
        if p == r or p.startswith(r.rstrip("/") + "/"):
            return True
    return False


def find_write_targets(cmd):
    """Best-effort extraction of write destinations from a Bash command.
    Covers redirects (`>`, `>>`, including `2>`/`&>`), `tee`, and `dd of=`.
    Cp/mv/rm/mkdir/touch positional args are not parsed — those are
    covered by SENSITIVE_PATH and PATH_DENY for the dangerous cases.
    """
    targets = []
    # Redirects: optional fd prefix, > or >>, optional quote, then path.
    # Excludes command-substitution constructs ($(...), `...`).
    for m in re.finditer(
        r"[12&]?>{1,2}\s*([\"']?)([^\s\"';|&<>`$]+)\1",
        cmd,
    ):
        targets.append(m.group(2))
    # tee with optional flags
    for m in re.finditer(
        r"\btee\b(?:\s+-\S+)*\s+([\"']?)([^\s\"';|&<>`$]+)\1",
        cmd,
    ):
        targets.append(m.group(2))
    # dd of=
    for m in re.finditer(r"\bdd\b[^|;&]*?\bof=([^\s|;&]+)", cmd):
        targets.append(m.group(1))
    return targets


def main():
    data = json.load(sys.stdin)
    if data.get("tool_name") != "Bash":
        sys.exit(0)
    cmd = data.get("tool_input", {}).get("command", "")
    if not cmd.strip():
        sys.exit(0)
    cwd = data.get("cwd") or ""
    mode = current_mode(cwd)

    # Explicit, opt-in escape hatch for a single UA-authorized privileged op.
    # OFF by default: the `sudo` catastrophic block stays fully in force for
    # every command unless CCG_ALLOW_SUDO_ONCE is set in the environment for
    # that specific invocation. Scoped further to the box-200 runner host via
    # the Hetzner jump host so a stray env var can't green-light arbitrary
    # local sudo. (2026-06-11, gitlab-runner-volume-prune cron install.)
    if (os.environ.get("CCG_ALLOW_SUDO_ONCE") == "1"
            and "ubuntu@10.10.0.200" in cmd
            and "168.119.2.111" in cmd):
        sys.exit(0)

    # SENSITIVE_PATH gets exempt-root paths stripped so legitimate access
    # to e.g. ~/.cyrus/credentials doesn't false-positive. All other
    # patterns (rm -rf, pipe-to-shell, etc.) still see the original cmd.
    sens_cmd = _strip_exempt_paths(cmd)

    # Hard-block patterns first (deny via exit 2).
    for pat, label, tier in PATTERNS:
        if mode == "build" and tier != "catastrophic":
            continue
        haystack = sens_cmd if pat is SENSITIVE_PATH else cmd
        if re.search(pat, haystack):
            print(f"bash-guard blocked: {label}", file=sys.stderr)
            print(f"  command: {cmd}", file=sys.stderr)
            print(f"  pattern: {pat}", file=sys.stderr)
            print(f"  mode:    {mode}", file=sys.stderr)
            print("  Edit ~/.claude/hooks/bash-guard.py to adjust.", file=sys.stderr)
            sys.exit(2)

    # Scope check: any write target outside cwd + WRITE_ALLOW_ROOTS → ask.
    # Skipped in build mode — when iterating, redirecting to /var/log/foo
    # or wherever shouldn't prompt.
    if cwd and mode != "build":
        for tgt in find_write_targets(cmd):
            tgt_abs = tgt if os.path.isabs(tgt) else os.path.join(cwd, tgt)
            if tgt in ALWAYS_OK_WRITE or tgt_abs in ALWAYS_OK_WRITE:
                continue
            if not in_allow_root(tgt_abs, cwd):
                ask(
                    f"bash write target outside project root and pre-approved roots: {tgt}\n"
                    f"(cwd={cwd}; pre-approved={', '.join(WRITE_ALLOW_ROOTS) or '(none)'})"
                )


if __name__ == "__main__":
    main()
