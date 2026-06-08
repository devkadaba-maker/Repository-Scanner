"""Dependency audit node — invokes the LangChain run_pip_audit tool."""

from __future__ import annotations

import json
from pathlib import Path

from auditagent.tools.scanner_tools import run_pip_audit


def dependency_audit_node(state: dict) -> dict:
    project_path = state["project_path"]
    findings = list(state.get("raw_findings", []))

    # pip-audit is Python-specific (and, with no requirements.txt/pyproject.toml,
    # falls back to auditing the *current* environment) — only run it when the
    # target actually looks like a Python project.
    root = Path(project_path)
    is_python_project = (
        "python" in state.get("tech_stack", {}).get("languages", ["python"])
        and ((root / "requirements.txt").exists() or (root / "pyproject.toml").exists())
    )
    if is_python_project:
        findings.extend(json.loads(run_pip_audit.invoke({"project_path": project_path})))

    return {**state, "raw_findings": findings}
