#!/usr/bin/env python3
"""PostToolUse: append a JSON line per tool call to a daily log.
Always exit 0 — audit hooks must never block.
"""
import json, sys, datetime, pathlib


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return

    log_dir = pathlib.Path.home() / ".claude" / "session-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{datetime.date.today().isoformat()}.jsonl"

    ti = data.get("tool_input", {}) or {}
    tool = data.get("tool_name", "?")
    detail = (
        ti.get("command") if tool == "Bash" else
        ti.get("file_path") if tool in ("Read", "Edit", "Write") else
        ti.get("pattern") if tool == "Grep" else
        ti.get("url") if tool == "WebFetch" else
        None
    )
    if isinstance(detail, str) and len(detail) > 4000:
        detail = detail[:4000] + "…(truncated)"

    entry = {
        "ts": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "session_id": data.get("session_id"),
        "cwd": data.get("cwd"),
        "tool": tool,
        "detail": detail,
        "is_error": (data.get("tool_response") or {}).get("isError", False),
    }
    with log_file.open("a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
