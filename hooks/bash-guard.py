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
    (r"\bgit\s+branch\s+[^|;&]*?-D\b",
        "git branch -D"),
    (r"\bgit\s+filter-branch\b",
        "git filter-branch"),
    (r"\bgit\s+config\s+[^|;&]*?core\.hooksPath\b",
        "git config core.hooksPath"),

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
    (r"\bnc\s+(?:[^|;&]*?\s)?-l\b",                "nc -l (listener)"),
    (r"\bnc\s+(?:[^|;&]*?\s)?-e\b",                "nc -e (command exec)"),
    (r"\bsocat\b",                                 "socat"),

    # Interpreter -c / -e: arbitrary code via Bash
    (r"\b(?:python|python3)\s+(?:[^|;&]*?\s)?-c\b",
        "python -c"),
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
