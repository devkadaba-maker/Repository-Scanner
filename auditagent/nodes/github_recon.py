"""
auditagent/nodes/github_recon.py

LangGraph-compatible recon node for GitHub-sourced repositories.

Extends the standard recon_node with GitHub-specific enrichment:
- Fetches rich metadata (description, stars, language, topics) via the API.
- Maps GitHub's detected language to the internal framework classification.
- Detects security-relevant files in the cloned repo:
    .env.example, Dockerfile, docker-compose.yml,
    .github/workflows/*.yml (CI/CD pipelines),
    requirements*.txt, pyproject.toml, setup.py/cfg.
- Merges all findings into state["tech_stack"]["github_metadata"].

The node is designed to be drop-in replaceable with ``recon_node`` when the
project originates from a GitHub clone.  It delegates the heavy lifting of
file-system walking to the standard recon_node and then enriches the result.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path
from typing import Any

from auditagent.nodes.recon import recon_node
from auditagent.github_integration import (
    GitHubIntegration,
    GitHubError,
    RepoInfo,
)

# ---------------------------------------------------------------------------
# GitHub language → internal framework name mapping
# ---------------------------------------------------------------------------
# GitHub's "language" field (primary language of the repo) maps to the same
# strings the standard recon node produces via FRAMEWORK_MARKERS scanning.
# When the API tells us the language we can make an educated initial guess
# that the per-file scanner will refine.

_LANG_TO_FRAMEWORK: dict[str, str] = {
    "python": "unknown",    # we still need per-file detection below
}

# If GitHub reports one of these as the primary language the repo is Python.
_PYTHON_LANGUAGES: frozenset[str] = frozenset(
    {"python", "jupyter notebook", "cython"}
)

# ---------------------------------------------------------------------------
# Security-relevant file patterns (relative to project root)
# ---------------------------------------------------------------------------
_SECURITY_FILE_PATTERNS: list[str] = [
    ".env.example",
    ".env.sample",
    ".env.template",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "requirements*.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Makefile",
    ".pre-commit-config.yaml",
    "tox.ini",
    ".bandit",
    "mypy.ini",
    ".mypy.ini",
    "pyrightconfig.json",
]


def _find_security_files(project_path: str) -> dict[str, list[str]]:
    """
    Walk the cloned repo and find files that are relevant to a security review.

    Returns a dict keyed by category:
    {
        "env_templates":  [...],
        "docker":         [...],
        "ci_cd":          [...],
        "dependency":     [...],
        "tooling":        [...],
    }
    """
    root = Path(project_path)

    found: dict[str, list[str]] = {
        "env_templates": [],
        "docker": [],
        "ci_cd": [],
        "dependency": [],
        "tooling": [],
    }

    def _rel(p: str) -> str:
        return os.path.relpath(p, project_path)

    # Env templates
    for pat in (".env.example", ".env.sample", ".env.template", ".env.dist"):
        f = root / pat
        if f.exists():
            found["env_templates"].append(_rel(str(f)))

    # Docker
    for pat in ("Dockerfile", "Dockerfile.*", "docker-compose.yml", "docker-compose.yaml"):
        for match in glob.glob(str(root / pat)):
            found["docker"].append(_rel(match))

    # CI/CD
    workflows_dir = root / ".github" / "workflows"
    if workflows_dir.exists():
        for wf in workflows_dir.glob("*.yml"):
            found["ci_cd"].append(_rel(str(wf)))
        for wf in workflows_dir.glob("*.yaml"):
            found["ci_cd"].append(_rel(str(wf)))

    # Dependency files
    for pat in ("requirements*.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "poetry.lock"):
        for match in glob.glob(str(root / pat)):
            found["dependency"].append(_rel(match))

    # Tooling / lint / type configs
    for name in (
        "Makefile", ".pre-commit-config.yaml", "tox.ini",
        ".bandit", "mypy.ini", ".mypy.ini", "pyrightconfig.json",
        ".flake8", ".pylintrc",
    ):
        f = root / name
        if f.exists():
            found["tooling"].append(_rel(str(f)))

    return found


def _build_github_metadata(
    repo_url: str,
    clone_result_metadata: dict[str, Any] | None,
    security_files: dict[str, list[str]],
    token: str | None,
) -> dict[str, Any]:
    """
    Assemble the github_metadata sub-dict that goes into tech_stack.

    First tries to use metadata already stored in state (from the clone step),
    then falls back to a fresh API call if needed.
    """
    meta: dict[str, Any] = {}

    if clone_result_metadata:
        meta.update(
            {
                "repo_name": clone_result_metadata.get("repo_name", ""),
                "full_name": clone_result_metadata.get("full_name", ""),
                "description": clone_result_metadata.get("description", ""),
                "default_branch": clone_result_metadata.get("default_branch", ""),
                "language": clone_result_metadata.get("language", ""),
                "stars": clone_result_metadata.get("stars", 0),
                "size_kb": clone_result_metadata.get("size_kb", 0),
                "clone_url": clone_result_metadata.get("clone_url", ""),
                "topics": clone_result_metadata.get("topics", []),
                "is_private": clone_result_metadata.get("is_private", False),
            }
        )
    elif repo_url:
        # Try a fresh API call (best-effort)
        try:
            gh = GitHubIntegration(token=token)
            info: RepoInfo = gh.get_repo_info(repo_url)
            meta.update(
                {
                    "repo_name": info["name"],
                    "full_name": info["full_name"],
                    "description": info["description"],
                    "default_branch": info["default_branch"],
                    "language": info["language"],
                    "stars": info["stars"],
                    "size_kb": info["size_kb"],
                    "clone_url": info["clone_url"],
                    "topics": info["topics"],
                    "is_private": info["is_private"],
                }
            )
        except GitHubError as exc:
            meta["api_error"] = str(exc)

    meta["security_files"] = security_files
    return meta


def _infer_framework_from_github_language(gh_language: str, current_framework: str) -> str:
    """
    If the per-file scanner returned 'unknown' and GitHub says Python, keep
    'unknown' so the LLM analysis doesn't get a false positive.  If GitHub
    tells us a specific framework language mapping, return it.

    In practice the per-file scanner is more accurate; we only override
    when it explicitly returned 'unknown'.
    """
    if current_framework != "unknown":
        return current_framework

    # GitHub can't detect Flask/FastAPI/Django — that needs per-file scanning.
    # We don't guess here; just return 'unknown' and let the LLM do its job.
    return "unknown"


# ---------------------------------------------------------------------------
# The node
# ---------------------------------------------------------------------------

def github_recon_node(state: dict) -> dict:
    """
    LangGraph node: GitHub-enriched reconnaissance.

    Expected state keys
    -------------------
    project_path : str
        Absolute path to the cloned repository.
    config : dict
        Must contain:
            github_token   : str | None — PAT for API calls (optional)
            github_url     : str | None — original GitHub URL
            github_metadata: dict | None — pre-fetched CloneResult fields
        Other keys (run_semgrep, run_exploit, model, output) are passed through.

    Returns
    -------
    dict
        Updated state with tech_stack enriched by a ``github_metadata`` key.
    """
    # ------------------------------------------------------------------
    # Step 1: Run the standard recon node to populate source_files,
    #         dependencies, framework, entrypoint, etc.
    # ------------------------------------------------------------------
    state = recon_node(state)

    # ------------------------------------------------------------------
    # Step 2: Extract GitHub-specific config
    # ------------------------------------------------------------------
    config: dict = state.get("config", {})
    github_token: str | None = config.get("github_token") or os.environ.get("GITHUB_TOKEN") or None
    github_url: str | None = config.get("github_url") or ""
    # CloneResult fields may have been stashed here by the API layer
    clone_meta: dict | None = config.get("github_metadata") or None

    project_path: str = state["project_path"]

    # ------------------------------------------------------------------
    # Step 3: Scan for security-relevant files in the cloned repo
    # ------------------------------------------------------------------
    security_files = _find_security_files(project_path)

    # ------------------------------------------------------------------
    # Step 4: Build github_metadata dict
    # ------------------------------------------------------------------
    github_metadata = _build_github_metadata(
        repo_url=github_url,
        clone_result_metadata=clone_meta,
        security_files=security_files,
        token=github_token,
    )

    # ------------------------------------------------------------------
    # Step 5: Enrich tech_stack
    # ------------------------------------------------------------------
    tech_stack: dict = state.get("tech_stack", {})

    # Refine framework guess using GitHub's language signal
    gh_language: str = github_metadata.get("language", "")
    current_framework: str = tech_stack.get("framework", "unknown")
    refined_framework = _infer_framework_from_github_language(gh_language, current_framework)
    tech_stack["framework"] = refined_framework

    # Surface key GitHub signals at the top level of tech_stack for
    # downstream nodes (e.g. the LLM analysis prompt builder)
    tech_stack["github_repo"] = github_metadata.get("full_name", "")
    tech_stack["github_language"] = gh_language
    tech_stack["github_topics"] = github_metadata.get("topics", [])
    tech_stack["github_description"] = github_metadata.get("description", "")
    tech_stack["has_docker"] = bool(security_files.get("docker"))
    tech_stack["has_ci_cd"] = bool(security_files.get("ci_cd"))
    tech_stack["has_env_template"] = bool(security_files.get("env_templates"))

    # Store the full metadata blob
    tech_stack["github_metadata"] = github_metadata

    return {
        **state,
        "tech_stack": tech_stack,
    }
