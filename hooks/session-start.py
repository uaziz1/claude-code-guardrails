#!/usr/bin/env python3
"""SessionStart: log environment + refuse to start on red flags in
project's .claude/settings.json (post-CVE-2025-59536 hygiene).
"""
import json, sys, os, pathlib, datetime, subprocess


def main():
    data = json.load(sys.stdin)
    cwd = data.get("cwd") or os.getcwd()

    flags = []
    for fname in (".claude/settings.json", ".claude/settings.local.json"):
        p = pathlib.Path(cwd) / fname
        if not p.exists():
            continue
        text = p.read_text(errors="ignore")

        # Substring checks for env-var names — their *presence* in any form
        # is the red flag (CVE-2026-21852-style endpoint redirection).
        for needle, label in [
            ("ANTHROPIC_BASE_URL", f"{fname}: ANTHROPIC_BASE_URL set"),
            ("OPENAI_BASE_URL",    f"{fname}: OPENAI_BASE_URL set"),
        ]:
            if needle in text:
                flags.append(label)

        try:
            cfg = json.loads(text)
        except Exception:
            cfg = None

        if isinstance(cfg, dict):
            # Boolean settings: only flag the truthy case. `: false` is benign
            # and a substring check would false-positive on it.
            def find_truthy(o, key):
                if isinstance(o, dict):
                    for k, v in o.items():
                        if k == key and v is True:
                            return True
                        if find_truthy(v, key):
                            return True
                elif isinstance(o, list):
                    return any(find_truthy(v, key) for v in o)
                return False

            for key, label in [
                ("enableAllProjectMcpServers", f"{fname}: enableAllProjectMcpServers: true"),
                ("autoApprove",                f"{fname}: autoApprove: true"),
            ]:
                if find_truthy(cfg, key):
                    flags.append(label)

            def walk(o):
                if isinstance(o, dict):
                    for v in o.values():
                        walk(v)
                elif isinstance(o, list):
                    for v in o:
                        walk(v)
                elif isinstance(o, str):
                    if any(s in o for s in ("curl ", "wget ", "bash -c", "$(", "`")):
                        flags.append(f"{fname}: suspicious hook command: {o[:120]}")

            walk(cfg.get("hooks", {}))

    log_dir = pathlib.Path.home() / ".claude" / "session-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{datetime.date.today().isoformat()}.jsonl"
    try:
        head = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=2,
        ).stdout.strip()
    except Exception:
        head = ""
    entry = {
        "ts": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "event": "session_start",
        "session_id": data.get("session_id"),
        "cwd": cwd,
        "git_head": head,
        "user": os.environ.get("USER"),
        "host": os.uname().nodename,
        "red_flags": flags,
    }
    with log_file.open("a") as f:
        f.write(json.dumps(entry) + "\n")

    if flags:
        print("session-start blocked: red flags in project Claude settings:", file=sys.stderr)
        for f in flags:
            print(f"  - {f}", file=sys.stderr)
        print("Inspect, remove, or bypass intentionally.", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
