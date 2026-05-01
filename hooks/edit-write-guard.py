#!/usr/bin/env python3
"""PreToolUse for Edit and Write: deny secret-shaped paths and credential
content. JSON-output decision (exit 2 is unreliable here per #13744).
"""
import json, sys, re, os


def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


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
    # macOS persistence
    (r"(^|/)Library/Launch(Agents|Daemons)/",        "macOS launchd persistence"),
    # Linux user-systemd persistence
    (r"(^|/)\.config/systemd/user/",                 "systemd user unit"),
    (r"(^|/)\.config/autostart/",                    "XDG autostart"),
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

    for cp in candidate_paths(path):
        for pat, label in PATH_DENY:
            if re.search(pat, cp, re.IGNORECASE):
                if cp != path:
                    deny(f"sensitive path: {label} (symlink {path} -> {cp})")
                deny(f"sensitive path: {label} ({cp})")

    for pat, label in CONTENT_DENY:
        if re.search(pat, content):
            deny(f"content contains {label}")


if __name__ == "__main__":
    main()
