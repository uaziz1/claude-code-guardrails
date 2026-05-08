"""Resolve the active guardrail mode for hooks.

Lookup order:
  1. <cwd>/.claude/guardrail-mode   (project scope — beats global)
  2. ~/.claude/guardrail-mode        (global scope)
  3. 'strict' (default with no file)

Modes:
  strict — all hook patterns enforce (default).
  build  — only patterns tagged 'catastrophic' enforce. Other patterns
           and the path-scope check are skipped. Credential-content
           scanning still runs in both modes.
"""
import os
from pathlib import Path

VALID_MODES = ("strict", "build")
DEFAULT_MODE = "strict"


def _read(p):
    try:
        if p.is_file():
            m = p.read_text(errors="ignore").strip().lower()
            if m in VALID_MODES:
                return m
    except Exception:
        pass
    return None


def current_mode(cwd=None):
    if cwd:
        m = _read(Path(cwd) / ".claude" / "guardrail-mode")
        if m:
            return m
    m = _read(Path.home() / ".claude" / "guardrail-mode")
    if m:
        return m
    return DEFAULT_MODE


def mode_with_source(cwd=None):
    """Return (mode, human description of which file set it) for banners."""
    if cwd:
        p = Path(cwd) / ".claude" / "guardrail-mode"
        m = _read(p)
        if m:
            return m, f"project: {p}"
    p = Path.home() / ".claude" / "guardrail-mode"
    m = _read(p)
    if m:
        return m, f"global: {p}"
    return DEFAULT_MODE, "default"
