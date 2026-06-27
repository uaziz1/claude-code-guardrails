"""Resolve the active guardrail mode for hooks.

Lookup order:
  1. <cwd>/.claude/guardrail-mode and any ANCESTOR up to (not including)
     $HOME — nearest wins (project scope — beats global). Walking up means a
     project's mode file at its root applies to every subdirectory (memory/,
     docs/, build scratchpads under it), not just when cwd is exactly the root.
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


def _project_mode(cwd):
    """Walk from cwd up toward the filesystem root, returning (mode, path) for
    the nearest `.claude/guardrail-mode`. Stops BEFORE $HOME so the home-level
    file is treated as global scope (handled by the caller), not project scope.
    """
    if not cwd:
        return None, None
    try:
        home = Path.home().resolve()
    except Exception:
        home = None
    try:
        p = Path(cwd).resolve()
    except Exception:
        p = Path(cwd)
    while True:
        if home is not None and p == home:
            break
        f = p / ".claude" / "guardrail-mode"
        m = _read(f)
        if m:
            return m, f
        if p == p.parent:  # reached filesystem root
            break
        p = p.parent
    return None, None


def current_mode(cwd=None):
    m, _ = _project_mode(cwd)
    if m:
        return m
    m = _read(Path.home() / ".claude" / "guardrail-mode")
    if m:
        return m
    return DEFAULT_MODE


def mode_with_source(cwd=None):
    """Return (mode, human description of which file set it) for banners."""
    m, p = _project_mode(cwd)
    if m:
        return m, f"project: {p}"
    p = Path.home() / ".claude" / "guardrail-mode"
    m = _read(p)
    if m:
        return m, f"global: {p}"
    return DEFAULT_MODE, "default"
