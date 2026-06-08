"""Shared utilities for auditagent nodes."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

DEFAULT_MODEL = "deepseek/deepseek-v4-flash"


def find_tool(name: str) -> str:
    """Return the tool path, preferring the same venv/bin as the current Python."""
    candidate = Path(sys.executable).parent / name
    if candidate.exists():
        return str(candidate)
    found = shutil.which(name)
    return found or name
