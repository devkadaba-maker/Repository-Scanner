"""LangChain @tool wrappers for bandit, semgrep, and pip-audit."""

from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

from langchain_core.tools import tool

from auditagent.utils import find_tool


SEVERITY_MAP = {
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
}

CVSS_TO_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "Low",
}


def _read_snippet(filepath: str, line: int, context: int = 3) -> str:
    try:
        lines = Path(filepath).read_text(errors="ignore").splitlines()
        start = max(0, line - 1 - context)
        end = min(len(lines), line + context)
        return "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))
    except OSError:
        return ""


@tool
def run_bandit(project_path: str) -> str:
    """Run bandit static security analysis on a Python project directory.

    Returns a JSON string containing a list of normalized Finding dicts.
    Each finding has: id, source, file, line, issue, severity, code_snippet, metadata.
    Returns an empty JSON array on failure.
    """
    findings: list[dict] = []
    try:
        result = subprocess.run(
            [find_tool("bandit"), "-r", project_path, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        data = json.loads(result.stdout or "{}")
        for item in data.get("results", []):
            filepath = item.get("filename", "")
            line = item.get("line_number", 0)
            sev_raw = item.get("issue_severity", "MEDIUM").upper()
            findings.append({
                "id": f"bandit-{item.get('test_id', 'B000')}-{uuid.uuid4().hex[:6]}",
                "source": "bandit",
                "file": filepath,
                "line": line,
                "issue": f"{item.get('test_id', '')} {item.get('issue_text', '')}".strip(),
                "severity": SEVERITY_MAP.get(sev_raw, "Medium"),
                "code_snippet": _read_snippet(filepath, line),
                "metadata": {
                    "test_id": item.get("test_id"),
                    "confidence": item.get("issue_confidence"),
                    "cwe": item.get("issue_cwe", {}).get("id"),
                    "more_info": item.get("more_info"),
                },
            })
    except FileNotFoundError:
        print("[warn] bandit not found — skipping static analysis")
    except subprocess.TimeoutExpired:
        print("[warn] bandit timed out")
    except json.JSONDecodeError as exc:
        print(f"[warn] bandit JSON parse error: {exc}")
    except Exception as exc:
        print(f"[warn] bandit error: {exc}")
    return json.dumps(findings)


@tool
def run_semgrep(project_path: str) -> str:
    """Run semgrep static analysis on a Python project directory.

    Returns a JSON string containing a list of normalized Finding dicts.
    Each finding has: id, source, file, line, issue, severity, code_snippet, metadata.
    Returns an empty JSON array on failure or if semgrep is not installed.
    """
    findings: list[dict] = []
    try:
        result = subprocess.run(
            [find_tool("semgrep"), "--config", "auto", "--json", project_path],
            capture_output=True,
            text=True,
            timeout=300,
        )
        data = json.loads(result.stdout or "{}")
        for item in data.get("results", []):
            filepath = item.get("path", "")
            start_line = item.get("start", {}).get("line", 0)
            sev_raw = item.get("extra", {}).get("severity", "WARNING").upper()
            meta = item.get("extra", {}).get("metadata", {})
            findings.append({
                "id": f"semgrep-{uuid.uuid4().hex[:6]}",
                "source": "semgrep",
                "file": filepath,
                "line": start_line,
                "issue": item.get("check_id", "semgrep-finding"),
                "severity": SEVERITY_MAP.get(sev_raw, "Medium"),
                "code_snippet": item.get("extra", {}).get("lines", ""),
                "metadata": {
                    "rule_id": item.get("check_id"),
                    "message": item.get("extra", {}).get("message", ""),
                    "cwe": meta.get("cwe"),
                    "owasp": meta.get("owasp"),
                    "references": meta.get("references", []),
                },
            })
    except FileNotFoundError:
        print("[warn] semgrep not found — skipping semgrep analysis")
    except subprocess.TimeoutExpired:
        print("[warn] semgrep timed out (it's slow on first run — use --no-semgrep to skip)")
    except json.JSONDecodeError as exc:
        print(f"[warn] semgrep JSON parse error: {exc}")
    except Exception as exc:
        print(f"[warn] semgrep error: {exc}")
    return json.dumps(findings)


@tool
def run_pip_audit(project_path: str) -> str:
    """Run pip-audit dependency vulnerability scan on a Python project directory.

    Scans requirements.txt or pyproject.toml for known CVEs.
    Returns a JSON string containing a list of normalized Finding dicts.
    Returns an empty JSON array on failure or when no vulnerabilities are found.
    """
    findings: list[dict] = []
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
        raw_out = result.stdout.strip()
        if not raw_out:
            return json.dumps(findings)
        data = json.loads(raw_out)
        deps = data if isinstance(data, list) else data.get("dependencies", [])
        for dep in deps:
            pkg_name = dep.get("name", "unknown")
            pkg_ver = dep.get("version", "?")
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "UNKNOWN")
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
                        "aliases": vuln.get("aliases", []),
                        "fix_versions": vuln.get("fix_versions", []),
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
    return json.dumps(findings)
