"""Static analysis node — invokes LangChain tools for bandit and semgrep."""

from __future__ import annotations

import json

from auditagent.tools.scanner_tools import run_bandit, run_semgrep


def static_analysis_node(state: dict) -> dict:
    project_path = state["project_path"]
    config = state.get("config", {})
    tech_stack = state.get("tech_stack", {})
    findings = list(state.get("raw_findings", []))

    # bandit is Python-specific — only run it on projects that contain Python source
    if "python" in tech_stack.get("languages", ["python"]):
        findings.extend(json.loads(run_bandit.invoke({"project_path": project_path})))

    # semgrep auto-detects every language it finds in the directory — it's our
    # language-agnostic scanner, so run it for all projects by default.
    if config.get("run_semgrep", True):
        findings.extend(json.loads(run_semgrep.invoke({"project_path": project_path})))

    return {**state, "raw_findings": findings}
