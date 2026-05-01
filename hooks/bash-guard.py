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
import json, re, sys


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


PATTERNS = [
    # rm with both -r/-R and -f flags in any order
    (r"\brm\s+-[A-Za-z]*[rR][A-Za-z]*[fF]\b",
        "rm -rf (or -fr / -Rf / -fR variant)"),
    (r"\brm\s+-[A-Za-z]*[fF][A-Za-z]*[rR]\b",
        "rm -fr (or -rf variant)"),
    (r"\brm\s+(?:[^|;&]*?\s)?--recursive\b[^|;&]*?--force\b",
        "rm --recursive --force"),
    (r"\brm\s+(?:[^|;&]*?\s)?--force\b[^|;&]*?--recursive\b",
        "rm --force --recursive"),

    # git destructive operations
    (r"\bgit\s+push\s+[^|;&]*?(?:--force(?!-with-lease)|-f\b)",
        "git push --force"),
    (r"\bgit\s+push\s+[^|;&]*?--force-with-lease\b",
        "git push --force-with-lease"),
    (r"\bgit\s+reset\s+[^|;&]*?--hard\b",
        "git reset --hard"),
    (r"\bgit\s+clean\s+[^|;&]*?-[A-Za-z]*f",
        "git clean -f"),
    (r"\bgit\s+checkout\s+--(\s|$)",
        "git checkout --"),
    (r"\bgit\s+checkout\s+\.(\s|$)",
        "git checkout ."),
    (r"\bgit\s+restore\b",
        "git restore"),
    (r"\bgit\s+branch\s+[^|;&]*?-D\b",
        "git branch -D"),
    (r"\bgit\s+filter-branch\b",
        "git filter-branch"),
    (r"\bgit\s+config\s+[^|;&]*?core\.hooksPath\b",
        "git config core.hooksPath"),
    (r"\bgit\s+stash\s+(?:drop|clear)\b",
        "git stash drop/clear"),
    (r"\bgit\s+update-ref\s+[^|;&]*?-d\b",
        "git update-ref -d"),
    (r"\bgit\s+submodule\s+deinit\s+[^|;&]*?-f\b",
        "git submodule deinit -f"),
    (r"\bgit\s+gc\s+[^|;&]*?--prune\b",
        "git gc --prune"),
    (r"\bgit\s+reflog\s+(?:expire|delete)\b",
        "git reflog expire/delete"),

    # System / privilege escalation
    (r"\bsudo\b",                                  "sudo"),
    (r"\bdoas\b",                                  "doas"),
    (r"\bpkexec\b",                                "pkexec"),
    (r"\beval\s",                                  "eval"),

    # Disk / filesystem destructive
    (r"\bdd\s+",                                   "dd"),
    (r"\bmkfs\.",                                  "mkfs.* (format filesystem)"),
    (r"\bshred\b",                                 "shred"),
    (r"\bwipefs\b",                                "wipefs"),
    (r">\s*/dev/(sd|nvme|disk[0-9]|hd|md)",        "redirect to block device"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:",                 "fork bomb"),

    # Network exfil / shell-from-stream
    (r"\b(?:curl|wget)\s+[^|;&]*?\|\s*(?:sh|bash|zsh|dash|ksh)\b",
        "curl|wget piped to shell"),
    # curl/wget saving to an executable-looking path → high odds of
    # download-then-execute on the next command.
    (r"\b(?:curl|wget)\s+[^|;&]*?(?:-o|--output|-O)\s+\S+\.(?:sh|bash|zsh|py|rb|pl|exe|bat|ps1|cmd|scr|jar)\b",
        "curl|wget output to script/executable"),
    (r"\bnc\s+(?:[^|;&]*?\s)?-l\b",                "nc -l (listener)"),
    (r"\bnc\s+(?:[^|;&]*?\s)?-e\b",                "nc -e (command exec)"),
    (r"\bsocat\b",                                 "socat"),

    # Shell -c: arbitrary inline command. The most direct bypass otherwise.
    (r"\b(?:bash|zsh|fish|ksh|dash|sh)\s+(?:[^|;&]*?\s)?-c\b",
        "shell -c (bash/zsh/fish/ksh/dash/sh)"),

    # Interpreter -c / -e / -m: arbitrary code via Bash
    (r"\b(?:python|python3|python2)\s+(?:[^|;&]*?\s)?-c\b",
        "python -c"),
    (r"\b(?:python|python3|python2)\s+(?:[^|;&]*?\s)?-m\b",
        "python -m (arbitrary module exec)"),
    (r"\b(?:node|deno)\s+(?:[^|;&]*?\s)?(?:-e|--eval)\b",
        "node/deno -e"),
    (r"\bperl\s+(?:[^|;&]*?\s)?-e\b",
        "perl -e"),
    (r"\bruby\s+(?:[^|;&]*?\s)?-e\b",
        "ruby -e"),

    # find -exec / -delete: arbitrary command execution per match
    (r"\bfind\s+[^|;&]*?-(?:exec|execdir|delete)\b",
        "find -exec / -execdir / -delete"),

    # Command substitution in command position (rare in legit usage)
    (r"(?:^|[;&|]\s*)\$\(",                        "$( ... ) as command"),
    (r"(?:^|[;&|]\s*)`",                           "backtick substitution as command"),

    # Sensitive-path access. Catches reads (cat/head/less/sed/grep/xxd/base64/
    # tee), copies/renames (cp/mv/ln) and exfil (scp/rsync) of credentials,
    # which would otherwise bypass the Edit/Write hook entirely.
    (SENSITIVE_PATH, "command references sensitive path"),
]


def main():
    data = json.load(sys.stdin)
    if data.get("tool_name") != "Bash":
        sys.exit(0)
    cmd = data.get("tool_input", {}).get("command", "")
    if not cmd.strip():
        sys.exit(0)

    for pat, label in PATTERNS:
        if re.search(pat, cmd):
            print(f"bash-guard blocked: {label}", file=sys.stderr)
            print(f"  command: {cmd}", file=sys.stderr)
            print(f"  pattern: {pat}", file=sys.stderr)
            print("  Edit ~/.claude/hooks/bash-guard.py to adjust.", file=sys.stderr)
            sys.exit(2)


if __name__ == "__main__":
    main()
