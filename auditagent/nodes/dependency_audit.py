"""Dependency audit node — runs pip-audit and normalises CVE findings."""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path

from auditagent.utils import find_tool


CVSS_TO_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "Low",
}


def _cvss_score_to_severity(score: float | None) -> str:
    if score is None:
        return "Medium"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _run_pip_audit(project_path: str) -> list[dict]:
    findings = []
    req_file = Path(project_path) / "requirements.txt"
    pyproject = Path(project_path) / "pyproject.toml"

    cmd = [find_tool("pip-audit"), "--format", "json", "--progress-spinner", "off"]
    if req_file.exists():
        cmd += ["-r", str(req_file)]
    elif pyproject.exists():
        cmd += ["--project", project_path]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=project_path,
        )
        # pip-audit exits 1 when vulns are found — that's expected
        raw_out = result.stdout.strip()
        if not raw_out:
            return findings
        data = json.loads(raw_out)

        # pip-audit JSON schema: list of {name, version, vulns: [{id, fix_versions, aliases, description}]}
        deps = data if isinstance(data, list) else data.get("dependencies", [])
        for dep in deps:
            pkg_name = dep.get("name", "unknown")
            pkg_ver = dep.get("version", "?")
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "UNKNOWN")
                aliases = vuln.get("aliases", [])
                fix_versions = vuln.get("fix_versions", [])
                # Use the severity field if pip-audit provides it; fall back to "Medium"
                sev_label = CVSS_TO_SEVERITY.get(
                    vuln.get("severity", "").lower(), "Medium"
                )
                findings.append({
                    "id": f"pip-audit-{vuln_id}-{uuid.uuid4().hex[:6]}",
                    "source": "pip-audit",
                    "file": "",
                    "line": 0,
                    "issue": f"{vuln_id} in {pkg_name}=={pkg_ver}",
                    "severity": sev_label,
                    "code_snippet": "",
                    "metadata": {
                        "package": pkg_name,
                        "version": pkg_ver,
                        "vuln_id": vuln_id,
                        "aliases": aliases,
                        "fix_versions": fix_versions,
                        "description": vuln.get("description", ""),
                    },
                })
    except FileNotFoundError:
        print("[warn] pip-audit not found — skipping dependency audit")
    except subprocess.TimeoutExpired:
        print("[warn] pip-audit timed out")
    except json.JSONDecodeError as exc:
        print(f"[warn] pip-audit JSON parse error: {exc}")
    except Exception as exc:
        print(f"[warn] pip-audit error: {exc}")
    return findings


def dependency_audit_node(state: dict) -> dict:
    project_path = state["project_path"]
    findings = list(state.get("raw_findings", []))
    findings.extend(_run_pip_audit(project_path))
    return {**state, "raw_findings": findings}
