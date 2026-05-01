#!/bin/bash
# install.sh — install claude-code-guardrails hooks into ~/.claude/
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOKS_DIR="$HOME/.claude/hooks"
LOGS_DIR="$HOME/.claude/session-logs"
SETTINGS_TEMPLATE="$REPO_DIR/templates/settings.json"

# OS detection. The hooks themselves are OS-agnostic — patterns for one
# OS simply don't match paths on another. But surfacing which patterns
# are *active* on this machine makes the install transparent.
detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macOS" ;;
        Linux)  echo "Linux" ;;
        *BSD)   echo "BSD" ;;
        MINGW*|MSYS*|CYGWIN*) echo "Windows-POSIX" ;;
        *)      echo "Unknown:$(uname -s)" ;;
    esac
}

# Extract platform-specific deny entries from the settings template by
# matching well-known path prefixes. This auto-syncs with the template
# instead of duplicating the pattern list here. POSIX-portable awk.
list_macos_patterns() {
    awk '/Library\/(Keychains|Cookies|LaunchAgents|LaunchDaemons)/ {
        gsub(/^[ \t]*"|"[ \t]*,?[ \t]*$/, ""); print "    " $0
    }' "$SETTINGS_TEMPLATE"
}
list_linux_patterns() {
    awk '/\/etc\/(shadow|sudoers|passwd)|\.config\/(systemd|autostart)/ {
        gsub(/^[ \t]*"|"[ \t]*,?[ \t]*$/, ""); print "    " $0
    }' "$SETTINGS_TEMPLATE"
}

OS=$(detect_os)
echo "==> Detected platform: $OS"
echo

echo "==> Creating $HOOKS_DIR and $LOGS_DIR"
mkdir -p "$HOOKS_DIR" "$LOGS_DIR"

echo "==> Copying hooks"
for f in bash-guard.py edit-write-guard.py audit.py session-start.py; do
    src="$REPO_DIR/hooks/$f"
    dst="$HOOKS_DIR/$f"
    # Idempotent: if dst already resolves to src (symlink/hardlink), skip
    # the copy. Otherwise BSD cp refuses identical-file overwrite under
    # `set -e` and the install would abort halfway.
    if [[ -e "$dst" && "$src" -ef "$dst" ]]; then
        echo "    $dst (already in place)"
    else
        cp "$src" "$dst"
        chmod +x "$dst"
        echo "    $dst"
    fi
done

echo
echo "==> Platform-specific deny patterns active on $OS:"
case "$OS" in
    macOS)
        list_macos_patterns
        echo "  (Linux/Unix patterns are also in the template but inert here.)"
        ;;
    Linux|BSD)
        list_linux_patterns
        echo "  (macOS patterns are also in the template but inert here.)"
        ;;
    *)
        echo "    (none — only cross-platform patterns will fire on $OS)"
        ;;
esac
echo
echo "Cross-platform patterns (rm -rf chains, sudo, eval, force-push, secrets,"
echo "shell -c, sensitive-path read/write, etc.) apply on every OS."

echo
echo "==> Settings"
if [[ -e "$HOME/.claude/settings.json" ]]; then
    cat <<EOF
You have an existing ~/.claude/settings.json. Manually merge the
"permissions" and "hooks" blocks from:

    $SETTINGS_TEMPLATE

into your file. A backup is recommended:

    cp ~/.claude/settings.json ~/.claude/settings.json.pre-guardrails.bak

EOF
else
    echo "No ~/.claude/settings.json found. Install the template?"
    read -r -p "    Copy templates/settings.json to ~/.claude/settings.json? [y/N] " yn
    if [[ "$yn" =~ ^[Yy]$ ]]; then
        cp "$SETTINGS_TEMPLATE" "$HOME/.claude/settings.json"
        echo "    Installed."
    else
        echo "    Skipped. See $SETTINGS_TEMPLATE when ready."
    fi
fi

echo
echo "Restart Claude Code; verify with /status."
echo "Run ./tests/run.sh to smoke-test the installed hooks."
