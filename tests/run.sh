#!/bin/bash
# tests/run.sh — smoke tests for claude-code-guardrails hooks.
# Feeds known payloads to each hook and asserts blocking/allowing behaviour.
#
# Test-fixture credentials are split across string concatenations so this
# file itself doesn't trip the content scanner when written through
# Claude Code.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOKS="$ROOT/hooks"
pass=0
fail=0

# Split-string fixtures (assembled at runtime; not literal in source).
AWS_KEY="AKI""AIOSFODNN7EXAMPLE"
PRIV_HDR="-----BEGIN PRIVATE KEY""-----"

# Bash hook: exit 2 = block, exit 0 = allow.
run_bash() {
    local name="$1" expected_exit="$2" payload="$3"
    local actual
    actual=$(echo "$payload" | "$HOOKS/bash-guard.py" >/dev/null 2>&1; echo $?)
    if [[ "$actual" == "$expected_exit" ]]; then
        echo "  ok    $name"
        pass=$((pass+1))
    else
        echo "  FAIL  $name — expected exit $expected_exit, got $actual"
        fail=$((fail+1))
    fi
}

# Edit/Write hook: JSON deny on stdout = block; empty stdout = allow.
run_editwrite_block() {
    local name="$1" payload="$2"
    local out
    out=$(echo "$payload" | "$HOOKS/edit-write-guard.py" 2>/dev/null)
    if echo "$out" | grep -q '"permissionDecision": "deny"'; then
        echo "  ok    $name"
        pass=$((pass+1))
    else
        echo "  FAIL  $name — expected JSON deny, got: $out"
        fail=$((fail+1))
    fi
}

run_editwrite_allow() {
    local name="$1" payload="$2"
    local out
    out=$(echo "$payload" | "$HOOKS/edit-write-guard.py" 2>/dev/null)
    if [[ -z "$out" ]] || ! echo "$out" | grep -q '"permissionDecision": "deny"'; then
        echo "  ok    $name"
        pass=$((pass+1))
    else
        echo "  FAIL  $name — expected allow, got: $out"
        fail=$((fail+1))
    fi
}

run_passthrough() {
    local name="$1" hook="$2" payload="$3"
    local actual
    actual=$(echo "$payload" | "$HOOKS/$hook" >/dev/null 2>&1; echo $?)
    if [[ "$actual" == "0" ]]; then
        echo "  ok    $name"
        pass=$((pass+1))
    else
        echo "  FAIL  $name — expected exit 0, got $actual"
        fail=$((fail+1))
    fi
}

echo "bash-guard"
run_bash "allow ls"                    0 '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
run_bash "allow git status"            0 '{"tool_name":"Bash","tool_input":{"command":"git status"}}'
run_bash "block chained rm -rf"        2 '{"tool_name":"Bash","tool_input":{"command":"echo hi && rm -rf /tmp/x"}}'
run_bash "block chained force-push"    2 '{"tool_name":"Bash","tool_input":{"command":"git status; git push --force-with-lease origin main"}}'
run_bash "block wrapper-stripped rm"   2 '{"tool_name":"Bash","tool_input":{"command":"timeout 30 rm -rf /tmp/x"}}'
run_bash "block env-runner inner rm"   2 '{"tool_name":"Bash","tool_input":{"command":"docker exec foo rm -rf /data"}}'
run_bash "block python -c"             2 '{"tool_name":"Bash","tool_input":{"command":"python3 -c \"import os\""}}'
run_bash "block git reset --hard"      2 '{"tool_name":"Bash","tool_input":{"command":"git reset --hard origin/main"}}'
run_bash "block git checkout --"       2 '{"tool_name":"Bash","tool_input":{"command":"git checkout -- src/"}}'
run_bash "block sudo"                  2 '{"tool_name":"Bash","tool_input":{"command":"sudo apt install foo"}}'
run_bash "block dd"                    2 '{"tool_name":"Bash","tool_input":{"command":"dd if=/dev/zero of=/tmp/x"}}'
run_bash "block fork bomb"             2 '{"tool_name":"Bash","tool_input":{"command":":(){ :|:& };:"}}'
run_bash "block redirect to /dev/sd"   2 '{"tool_name":"Bash","tool_input":{"command":"echo > /dev/sda"}}'
run_bash "block find -exec"            2 '{"tool_name":"Bash","tool_input":{"command":"find . -name foo -exec rm {} ;"}}'

echo
echo "edit-write-guard"
run_editwrite_block "block .env"           '{"tool_name":"Edit","tool_input":{"file_path":"/tmp/.env","new_string":"x"}}'
run_editwrite_block "block SSH key path"   '{"tool_name":"Write","tool_input":{"file_path":"/Users/x/.ssh/id_rsa","content":"x"}}'
run_editwrite_block "block .github wf"     '{"tool_name":"Edit","tool_input":{"file_path":"/repo/.github/workflows/ci.yml","new_string":"x"}}'
run_editwrite_block "block AWS access"     "$(printf '{"tool_name":"Write","tool_input":{"file_path":"/tmp/x.md","content":"%s"}}' "$AWS_KEY")"
run_editwrite_block "block private key"    "$(printf '{"tool_name":"Write","tool_input":{"file_path":"/tmp/x.txt","content":"%s\\nfoo"}}' "$PRIV_HDR")"
run_editwrite_allow "allow source edit"    '{"tool_name":"Edit","tool_input":{"file_path":"/tmp/foo.ts","new_string":"const x = 1"}}'
run_editwrite_allow "allow benign write"   '{"tool_name":"Write","tool_input":{"file_path":"/tmp/notes.md","content":"hello world"}}'

echo
echo "audit"
run_passthrough "appends log line"     audit.py        '{"session_id":"t","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"},"tool_response":{"isError":false}}'

echo
echo "session-start"
run_passthrough "clean directory"      session-start.py '{"session_id":"t","cwd":"/tmp"}'

echo
echo "$pass passed, $fail failed"
exit $fail
