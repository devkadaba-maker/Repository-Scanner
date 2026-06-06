"""Recon node — walks the project, detects tech stack, lists source files and deps."""

from __future__ import annotations

import os
import re
from pathlib import Path

SKIP_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__", ".tox", "dist", "build"}

FRAMEWORK_MARKERS = {
    "flask": re.compile(r"(?:from|import)\s+flask", re.I),
    "fastapi": re.compile(r"(?:from|import)\s+fastapi", re.I),
    "django": re.compile(r"(?:from|import)\s+django|DJANGO_SETTINGS_MODULE", re.I),
}

ENTRYPOINT_NAMES = ["app.py", "main.py", "wsgi.py", "asgi.py", "manage.py", "run.py", "server.py"]


def _detect_framework(source_files: list[str]) -> str:
    for fpath in source_files[:50]:  # scan first 50 files to keep it fast
        try:
            text = Path(fpath).read_text(errors="ignore")
        except OSError:
            continue
        for fw, pat in FRAMEWORK_MARKERS.items():
            if pat.search(text):
                return fw
    return "unknown"


def _detect_entrypoint(project_path: str, source_files: list[str]) -> str:
    root = Path(project_path)
    # prefer project root entrypoints
    for name in ENTRYPOINT_NAMES:
        candidate = root / name
        if candidate.exists():
            return str(candidate)
    # fall back to first source file
    return source_files[0] if source_files else ""


def _parse_requirements(project_path: str) -> list[str]:
    deps: list[str] = []
    root = Path(project_path)

    req_file = root / "requirements.txt"
    if req_file.exists():
        for line in req_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                deps.append(line)

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            try:
                import tomli as tomllib  # noqa: F401
            except ImportError:
                tomllib = None  # type: ignore

        if tomllib:
            try:
                data = tomllib.loads(pyproject.read_text())
                # PEP 621
                proj_deps = data.get("project", {}).get("dependencies", [])
                deps.extend(proj_deps)
                # Poetry
                poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                for pkg, ver in poetry_deps.items():
                    if pkg.lower() == "python":
                        continue
                    if isinstance(ver, str):
                        deps.append(f"{pkg}{ver}" if ver.startswith(("^", "~", ">", "<", "=")) else f"{pkg}=={ver}")
                    else:
                        deps.append(pkg)
            except Exception:
                pass

    return list(dict.fromkeys(deps))  # deduplicate, preserve order


def recon_node(state: dict) -> dict:
    project_path = os.path.abspath(state["project_path"])
    source_files: list[str] = []

    for dirpath, dirnames, filenames in os.walk(project_path):
        # Prune skipped dirs in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith(".py"):
                source_files.append(os.path.join(dirpath, fname))

    framework = _detect_framework(source_files)
    entrypoint = _detect_entrypoint(project_path, source_files)
    dependencies = _parse_requirements(project_path)

    tech_stack = {
        "framework": framework,
        "entrypoint": entrypoint,
        "python_version": "3.11",
        "source_file_count": len(source_files),
    }

    return {
        **state,
        "project_path": project_path,
        "source_files": source_files,
        "dependencies": dependencies,
        "tech_stack": tech_stack,
    }
