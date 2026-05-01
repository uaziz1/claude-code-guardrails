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
        for needle, label in [
            ("ANTHROPIC_BASE_URL",          f"{fname}: ANTHROPIC_BASE_URL set"),
            ("OPENAI_BASE_URL",             f"{fname}: OPENAI_BASE_URL set"),
            ("enableAllProjectMcpServers",  f"{fname}: enableAllProjectMcpServers"),
            ("autoApprove",                 f"{fname}: autoApprove"),
        ]:
            if needle in text:
                flags.append(label)
        try:
            cfg = json.loads(text)

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
        except Exception:
            pass

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
