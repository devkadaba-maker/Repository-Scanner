"""Recon node — walks the project, detects tech stack, lists source files and deps."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

SKIP_DIRS = {
    ".venv", "venv", "node_modules", ".git", "__pycache__", ".tox", "dist", "build",
    "vendor", "target", ".next", ".gradle", "bin", "obj",
}

# Extension → language, used for source-file collection and the language breakdown
# in tech_stack. Drives which Python-only tools (bandit, pip-audit) are gated on.
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".swift": "swift",
    ".scala": "scala",
}

FRAMEWORK_MARKERS = {
    "flask": re.compile(r"(?:from|import)\s+flask", re.I),
    "fastapi": re.compile(r"(?:from|import)\s+fastapi", re.I),
    "django": re.compile(r"(?:from|import)\s+django|DJANGO_SETTINGS_MODULE", re.I),
    "express": re.compile(r"require\(['\"]express['\"]\)|from\s+['\"]express['\"]", re.I),
    "next.js": re.compile(r"from\s+['\"]next(?:/|['\"])", re.I),
    "react": re.compile(r"from\s+['\"]react['\"]|require\(['\"]react['\"]\)", re.I),
    "nestjs": re.compile(r"from\s+['\"]@nestjs/", re.I),
    "spring": re.compile(r"org\.springframework", re.I),
    "rails": re.compile(r"Rails\.application|ActionController::Base", re.I),
    "laravel": re.compile(r"Illuminate\\\\|use\s+Illuminate", re.I),
    "gin": re.compile(r"github\.com/gin-gonic/gin", re.I),
    "actix": re.compile(r"actix_web", re.I),
}

ENTRYPOINT_NAMES = [
    "app.py", "main.py", "wsgi.py", "asgi.py", "manage.py", "run.py", "server.py",
    "index.js", "index.ts", "server.js", "server.ts", "app.js", "app.ts", "main.go",
    "Main.java", "Program.cs", "main.rs",
]


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
    for name in ENTRYPOINT_NAMES:
        candidate = root / name
        if candidate.exists():
            return str(candidate)
    return source_files[0] if source_files else ""


def _parse_requirements(project_path: str) -> list[str]:
    deps: list[str] = []
    root = Path(project_path)

    req_file = root / "requirements.txt"
    if req_file.exists():
        for line in req_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r ") or line.startswith("-r\t"):
                # Recursively parse referenced requirement files
                ref_path = root / line[3:].strip()
                if ref_path.exists():
                    deps.extend(_parse_requirements(str(ref_path.parent)))
                continue
            if line.startswith("-"):
                continue  # skip other pip options (-c, -e, etc.)
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
    language_counts: dict[str, int] = {}

    for dirpath, dirnames, filenames in os.walk(project_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            ext = Path(fname).suffix.lower()
            lang = LANGUAGE_EXTENSIONS.get(ext)
            if lang:
                fpath = os.path.join(dirpath, fname)
                source_files.append(fpath)
                language_counts[lang] = language_counts.get(lang, 0) + 1

    languages = sorted(language_counts, key=language_counts.get, reverse=True)
    primary_language = languages[0] if languages else "unknown"

    framework = _detect_framework(source_files)
    entrypoint = _detect_entrypoint(project_path, source_files)
    dependencies = _parse_requirements(project_path)

    tech_stack = {
        "framework": framework,
        "entrypoint": entrypoint,
        "language": primary_language,
        "languages": languages,
        "language_counts": language_counts,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "source_file_count": len(source_files),
    }

    return {
        **state,
        "project_path": project_path,
        "source_files": source_files,
        "dependencies": dependencies,
        "tech_stack": tech_stack,
    }
