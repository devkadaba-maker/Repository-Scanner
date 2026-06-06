"""Dependency audit node — invokes the LangChain run_pip_audit tool."""

from __future__ import annotations

import json

from auditagent.tools.scanner_tools import run_pip_audit


def dependency_audit_node(state: dict) -> dict:
    project_path = state["project_path"]
    findings = list(state.get("raw_findings", []))
    findings.extend(json.loads(run_pip_audit.invoke({"project_path": project_path})))
    return {**state, "raw_findings": findings}
