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
    (r"(^|/)\.env($|[./])",                          ".env file"),
    (r"\.(pem|key|crt|p12|pfx)$",                    "credential/cert file"),
    (r"(^|/)id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$",    "SSH key"),
    (r"(^|/)\.ssh/",                                 "~/.ssh path"),
    (r"(^|/)\.aws/",                                 "~/.aws path"),
    (r"(^|/)\.kube/config$",                         "kubeconfig"),
    (r"(^|/)\.netrc$",                               ".netrc"),
    (r"(^|/)\.npmrc$",                               ".npmrc"),
    (r"(^|/)\.pypirc$",                              ".pypirc"),
    (r"(^|/)\.github/workflows/",                    "GitHub Actions workflow"),
    (r"(^|/)\.claude/(?!session-logs/)",             "Claude config (not log dir)"),
    (r"(^|/)\.mcp\.json$",                           "MCP config"),
    (r"(^|/)\.husky/",                               "git hook"),
    (r"(^|/)\.git/(?!info/)",                        ".git internals"),
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
    (r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----", "private key block"),
    (r"xox[abpr]-[A-Za-z0-9-]{10,}",                   "Slack token"),
]


def main():
    data = json.load(sys.stdin)
    if data.get("tool_name") not in ("Edit", "Write"):
        sys.exit(0)
    ti = data.get("tool_input", {}) or {}
    path = (ti.get("file_path") or "").replace(os.sep, "/")
    content = ti.get("content") or ti.get("new_string") or ""

    for pat, label in PATH_DENY:
        if re.search(pat, path):
            deny(f"sensitive path: {label} ({path})")

    for pat, label in CONTENT_DENY:
        if re.search(pat, content):
            deny(f"content contains {label}")


if __name__ == "__main__":
    main()
