"""Static analysis node — runs bandit (always) and semgrep (optional)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path


def _tool_path(name: str) -> str:
    """Return the tool path, preferring the same venv/bin as the current Python."""
    # Look next to sys.executable first (covers venv installs)
    candidate = Path(sys.executable).parent / name
    if candidate.exists():
        return str(candidate)
    # Fall back to whatever's on PATH
    found = shutil.which(name)
    return found or name


SEVERITY_MAP = {
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
}


def _read_snippet(filepath: str, line: int, context: int = 3) -> str:
    try:
        lines = Path(filepath).read_text(errors="ignore").splitlines()
        start = max(0, line - 1 - context)
        end = min(len(lines), line + context)
        numbered = [f"{i + 1}: {lines[i]}" for i in range(start, end)]
        return "\n".join(numbered)
    except OSError:
        return ""


def _run_bandit(project_path: str) -> list[dict]:
    findings = []
    try:
        result = subprocess.run(
            [_tool_path("bandit"), "-r", project_path, "-f", "json", "-q"],
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
                "severity": SEVERITY_MAP.get(sev_raw, sev_raw),
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
    except (json.JSONDecodeError, Exception) as exc:
        print(f"[warn] bandit parsing error: {exc}")
    return findings


def _run_semgrep(project_path: str) -> list[dict]:
    findings = []
    try:
        result = subprocess.run(
            [_tool_path("semgrep"), "--config", "auto", "--json", project_path],
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
                "severity": SEVERITY_MAP.get(sev_raw, sev_raw),
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
    except (json.JSONDecodeError, Exception) as exc:
        print(f"[warn] semgrep parsing error: {exc}")
    return findings


def static_analysis_node(state: dict) -> dict:
    project_path = state["project_path"]
    config = state.get("config", {})
    findings = list(state.get("raw_findings", []))

    findings.extend(_run_bandit(project_path))

    if config.get("run_semgrep", False):
        findings.extend(_run_semgrep(project_path))

    return {**state, "raw_findings": findings}
