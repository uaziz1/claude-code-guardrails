#!/usr/bin/env python3
"""PreToolUse for Edit and Write: deny secret-shaped paths and credential
content. JSON-output decision (exit 2 is unreliable here per #13744).
"""
import json, sys, re, os


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


PATH_DENY = [
    (r"(^|/)\.env(?!\.example|\.sample|\.template|\.dist|\.test)($|[./])", ".env file"),
    (r"\.(pem|key|crt|p12|pfx)$",                    "credential/cert file"),
    (r"(^|/)id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$",    "SSH key"),
    (r"(^|/)\.ssh/",                                 "~/.ssh path"),
    (r"(^|/)\.aws/",                                 "~/.aws path"),
    (r"(^|/)\.gnupg/",                               "~/.gnupg path"),
    (r"(^|/)\.kube/config$",                         "kubeconfig"),
    (r"(^|/)\.netrc$",                               ".netrc"),
    (r"(^|/)\.npmrc$",                               ".npmrc"),
    (r"(^|/)\.pypirc$",                              ".pypirc"),
    (r"(^|/)\.github/workflows/",                    "GitHub Actions workflow"),
    (r"(^|/)\.claude/(?!session-logs/|projects/[^/]+/memory/)", "Claude config (not log/memory dirs)"),
    (r"(^|/)\.mcp\.json$",                           "MCP config"),
    (r"(^|/)\.husky/",                               "git hook"),
    (r"(^|/)\.git/(?!info/)",                        ".git internals"),
    # Shell-startup persistence vectors
    (r"(^|/)\.(bash|zsh)rc$",                        "shell rc file"),
    (r"(^|/)\.(bash_profile|zshenv|zprofile|profile)$", "shell profile"),
    (r"(^|/)\.bash_logout$",                         "shell logout file"),
    # macOS persistence + secret stores
    (r"(^|/)Library/Launch(Agents|Daemons)/",        "macOS launchd persistence"),
    (r"(^|/)Library/Keychains/",                     "macOS keychain"),
    (r"(^|/)Library/Cookies/",                       "macOS browser cookies"),
    # Linux user-systemd persistence + system credential stores
    (r"(^|/)\.config/systemd/user/",                 "systemd user unit"),
    (r"(^|/)\.config/autostart/",                    "XDG autostart"),
    (r"^/etc/(shadow|sudoers|passwd)$",              "Unix system credential file"),
    (r"^/etc/sudoers\.d/",                           "sudoers.d entry"),
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

    # Hard denylist first. PATH_DENY wins over scope: if a sensitive
    # path is requested, even one inside CWD, we block.
    for cp in candidate_paths(path):
        for pat, label in PATH_DENY:
            if re.search(pat, cp, re.IGNORECASE):
                if cp != path:
                    deny(f"sensitive path: {label} (symlink {path} -> {cp})")
                deny(f"sensitive path: {label} ({cp})")

    for pat, label in CONTENT_DENY:
        if re.search(pat, content):
            deny(f"content contains {label}")

    # Scope check (principle of least privilege). Inside CWD or a
    # pre-approved root → silent allow. Anywhere else → `ask`, so the
    # user approves the first time. Sensitive paths already denied above.
    if path and cwd and not in_allow_root(path, cwd):
        ask(
            f"write outside project root and pre-approved roots: {path}\n"
            f"(cwd={cwd}; pre-approved={', '.join(WRITE_ALLOW_ROOTS) or '(none)'})"
        )


if __name__ == "__main__":
    main()
