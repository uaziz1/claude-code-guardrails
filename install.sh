#!/bin/bash
# install.sh — install claude-code-guardrails hooks into ~/.claude/
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOKS_DIR="$HOME/.claude/hooks"
LOGS_DIR="$HOME/.claude/session-logs"

echo "==> Creating $HOOKS_DIR and $LOGS_DIR"
mkdir -p "$HOOKS_DIR" "$LOGS_DIR"

echo "==> Copying hooks"
for f in bash-guard.py edit-write-guard.py audit.py session-start.py; do
    cp "$REPO_DIR/hooks/$f" "$HOOKS_DIR/$f"
    chmod +x "$HOOKS_DIR/$f"
    echo "    $HOOKS_DIR/$f"
done

echo
echo "Hooks installed. Next step: settings.json."
echo
if [[ -e "$HOME/.claude/settings.json" ]]; then
    cat <<EOF
You have an existing ~/.claude/settings.json. Manually merge the
"permissions" and "hooks" blocks from:

    $REPO_DIR/templates/settings.json

into your file. A backup is recommended:

    cp ~/.claude/settings.json ~/.claude/settings.json.pre-guardrails.bak

EOF
else
    echo "No ~/.claude/settings.json found. Install the template?"
    read -r -p "    Copy templates/settings.json to ~/.claude/settings.json? [y/N] " yn
    if [[ "$yn" =~ ^[Yy]$ ]]; then
        cp "$REPO_DIR/templates/settings.json" "$HOME/.claude/settings.json"
        echo "    Installed."
    else
        echo "    Skipped. See $REPO_DIR/templates/settings.json when ready."
    fi
fi

echo
echo "Restart Claude Code; verify with /status."
echo "Run ./tests/run.sh to smoke-test the installed hooks."
