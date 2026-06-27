#!/usr/bin/env python3
"""PreToolUse for Edit and Write: deny secret-shaped paths and credential
content. JSON-output decision (exit 2 is unreliable here per #13744).
"""
import json, sys, re, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mode import current_mode  # noqa: E402


def _decide(decision, reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def deny(reason):
    _decide("deny", reason)


def ask(reason):
    _decide("ask", reason)


# Roots inside which writes are pre-approved without prompting. The
# project CWD is always allowed; this list extends that with common
# transient/cache locations every workflow needs. Anything *outside*
# both is `ask` — the user approves the first time and Claude Code
# remembers within the session. Edit this list to pre-approve more.
_HOME = os.path.expanduser("~")
WRITE_ALLOW_ROOTS = [r for r in (
    "/tmp",
    "/private/tmp",                        # macOS resolves /tmp here
    "/var/tmp",
    os.environ.get("TMPDIR", "").rstrip("/") or None,
    os.path.join(_HOME, ".cache"),         # XDG cache (Linux + cross-platform tools)
    os.path.join(_HOME, "Library/Caches"), # macOS — harmless on other OSes
    os.path.join(_HOME, ".claude/projects"),  # auto-memory dir — CWD differs from canonical project path under worktrees (e.g. Conductor)
) if r]
# Optional comma-separated env-var override for project-specific roots
# without editing this file.
WRITE_ALLOW_ROOTS += [
    r.rstrip("/") for r in os.environ.get("CCG_WRITE_ALLOW_ROOTS", "").split(",") if r.strip()
]


def _resolve(path):
    try:
        return os.path.realpath(path)
    except Exception:
        return path


def in_allow_root(path, cwd):
    """True if the resolved path is inside cwd or any WRITE_ALLOW_ROOTS entry."""
    if not path:
        return False
    p = _resolve(path)
    for root in ([cwd] if cwd else []) + WRITE_ALLOW_ROOTS:
        if not root:
            continue
        r = _resolve(root)
        if p == r or p.startswith(r.rstrip("/") + "/"):
            return True
    return False


# Each entry is (pattern, label, tier). Tier "catastrophic" enforces in
# both modes; "strict" is dropped in build mode. Build mode keeps secret
# stores, system credential files, and OS persistence vectors locked
# down, while letting the agent edit the project's own .env / .git /
# .github / .claude / etc. when iterating.
PATH_DENY = [
    (r"(^|/)\.env(?!\.example|\.sample|\.template|\.dist|\.test)($|[./])", ".env file", "catastrophic"),
    (r"\.(pem|key|crt|p12|pfx)$",                    "credential/cert file", "catastrophic"),
    (r"(^|/)id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$",    "SSH key", "catastrophic"),
    (r"(^|/)\.ssh/",                                 "~/.ssh path", "catastrophic"),
    (r"(^|/)\.aws/",                                 "~/.aws path", "catastrophic"),
    (r"(^|/)\.gnupg/",                               "~/.gnupg path", "catastrophic"),
    (r"(^|/)\.kube/config$",                         "kubeconfig", "catastrophic"),
    (r"(^|/)\.netrc$",                               ".netrc", "catastrophic"),
    (r"(^|/)\.npmrc$",                               ".npmrc", "catastrophic"),
    (r"(^|/)\.pypirc$",                              ".pypirc", "catastrophic"),
    (r"(^|/)\.github/workflows/",                    "GitHub Actions workflow", "strict"),
    (r"(^|/)\.claude/(?!session-logs/|projects/(canonical/)?[^/]+/(memory|10-sessions)/)", "Claude config (not log/memory dirs)", "strict"),
    (r"(^|/)\.mcp\.json$",                           "MCP config", "strict"),
    (r"(^|/)\.husky/",                               "git hook", "strict"),
    (r"(^|/)\.git/(?!info/)",                        ".git internals", "strict"),
    # Shell-startup persistence vectors
    (r"(^|/)\.(bash|zsh)rc$",                        "shell rc file", "strict"),
    (r"(^|/)\.(bash_profile|zshenv|zprofile|profile)$", "shell profile", "strict"),
    (r"(^|/)\.bash_logout$",                         "shell logout file", "strict"),
    # macOS persistence + secret stores
    (r"(^|/)Library/Launch(Agents|Daemons)/",        "macOS launchd persistence", "catastrophic"),
    (r"(^|/)Library/Keychains/",                     "macOS keychain", "catastrophic"),
    (r"(^|/)Library/Cookies/",                       "macOS browser cookies", "catastrophic"),
    # Linux user-systemd persistence + system credential stores
    (r"(^|/)\.config/systemd/user/",                 "systemd user unit", "catastrophic"),
    (r"(^|/)\.config/autostart/",                    "XDG autostart", "catastrophic"),
    (r"^/etc/(shadow|sudoers|passwd)$",              "Unix system credential file", "catastrophic"),
    (r"^/etc/sudoers\.d/",                           "sudoers.d entry", "catastrophic"),
]

CONTENT_DENY = [
    (r"AKIA[0-9A-Z]{16}",                              "AWS access key"),
    (r"ASIA[0-9A-Z]{16}",                              "AWS temp access key"),
    (r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}", "AWS secret"),
    (r"ghp_[A-Za-z0-9]{36}",                           "GitHub PAT"),
    (r"gho_[A-Za-z0-9]{36}",                           "GitHub OAuth token"),
    (r"ghs_[A-Za-z0-9]{36}",                           "GitHub server token"),
    (r"github_pat_[A-Za-z0-9_]{82}",                   "fine-grained GitHub PAT"),
    (r"sk_live_[A-Za-z0-9]{24,}",                      "Stripe live key"),
    (r"sk-ant-[A-Za-z0-9_-]{40,}",                     "Anthropic API key"),
    (r"sk-proj-[A-Za-z0-9_-]{40,}",                    "OpenAI project key"),
    (r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----", "private key block"),
    (r"xox[abpr]-[A-Za-z0-9-]{10,}",                   "Slack token"),
    (r"npm_[A-Za-z0-9]{36}",                           "npm token"),
    (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",      "SendGrid API key"),
    (r"\"type\":\s*\"service_account\"",                "GCP service-account JSON"),
]


def candidate_paths(path):
    """Return the requested path plus its symlink-resolved target, if
    different. Symlink-aware so `ln -sf ~/.ssh/id_rsa /tmp/x; Edit /tmp/x`
    still trips PATH_DENY.
    """
    out = [path]
    try:
        real = os.path.realpath(path)
        if real and real != path:
            out.append(real.replace(os.sep, "/"))
    except Exception:
        pass
    return out


def main():
    data = json.load(sys.stdin)
    if data.get("tool_name") not in ("Edit", "Write"):
        sys.exit(0)
    ti = data.get("tool_input", {}) or {}
    path = (ti.get("file_path") or "").replace(os.sep, "/")
    content = ti.get("content") or ti.get("new_string") or ""
    cwd = data.get("cwd") or ""
    mode = current_mode(cwd)

    # Hard denylist first. PATH_DENY wins over scope: if a sensitive
    # path is requested, even one inside CWD, we block.
    for cp in candidate_paths(path):
        for pat, label, tier in PATH_DENY:
            if mode == "build" and tier != "catastrophic":
                continue
            if re.search(pat, cp, re.IGNORECASE):
                if cp != path:
                    deny(f"sensitive path: {label} (symlink {path} -> {cp})")
                deny(f"sensitive path: {label} ({cp})")

    # CONTENT_DENY (credential exfil) always runs — secrets in code are
    # never legitimate, regardless of mode.
    for pat, label in CONTENT_DENY:
        if re.search(pat, content):
            deny(f"content contains {label}")

    # Scope check (principle of least privilege). Skipped in build mode
    # — when iterating, writing outside cwd shouldn't prompt.
    if path and cwd and mode != "build" and not in_allow_root(path, cwd):
        ask(
            f"write outside project root and pre-approved roots: {path}\n"
            f"(cwd={cwd}; pre-approved={', '.join(WRITE_ALLOW_ROOTS) or '(none)'})"
        )


if __name__ == "__main__":
    main()
