"""Static analysis node — invokes LangChain tools for bandit and semgrep."""

from __future__ import annotations

import json

from auditagent.tools.scanner_tools import run_bandit, run_semgrep


def static_analysis_node(state: dict) -> dict:
    project_path = state["project_path"]
    config = state.get("config", {})
    findings = list(state.get("raw_findings", []))

    findings.extend(json.loads(run_bandit.invoke({"project_path": project_path})))

    if config.get("run_semgrep", False):
        findings.extend(json.loads(run_semgrep.invoke({"project_path": project_path})))

    return {**state, "raw_findings": findings}
