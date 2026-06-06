"""Shared state TypedDicts for the audit LangGraph pipeline."""

from __future__ import annotations

from typing import TypedDict


class Finding(TypedDict):
    """Normalized finding from bandit, semgrep, or pip-audit."""
    id: str                  # unique slug, e.g. "bandit-B608-app.py-42"
    source: str              # "bandit" | "semgrep" | "pip-audit"
    file: str                # absolute or project-relative path (empty for dep findings)
    line: int                # source line (0 for dep findings)
    issue: str               # short issue name / CVE id
    severity: str            # raw severity string from the tool
    code_snippet: str        # extracted source lines around the finding
    metadata: dict           # tool-specific extras (test_id, cve_id, fix_version, …)


class LLMFinding(TypedDict):
    """Finding enriched by the LLM analysis node."""
    finding: Finding
    confirmed: bool          # LLM confirms it's a real vulnerability
    severity: str            # Critical | High | Medium | Low
    attack_vector: str       # brief description of how an attacker exploits this
    explanation: str         # full LLM explanation
    fix: str                 # LLM-suggested remediation
    exploitable: bool        # LLM judges it practically exploitable


class ExploitResult(TypedDict):
    """Result of the safe local exploitation node."""
    finding_id: str
    poc: str                 # the PoC script / curl command generated
    executed: bool           # whether the PoC was actually run
    verdict: str             # "Exploitable" | "Not exploitable" | "Inconclusive"
    evidence: str            # captured request/response or error output
    impact: str              # brief impact statement from LLM


class AuditState(TypedDict):
    """Full mutable state carried through the LangGraph pipeline."""
    project_path: str
    tech_stack: dict          # {framework, entrypoint, python_version, …}
    source_files: list        # list of str paths
    dependencies: list        # list of str "package==version" entries
    raw_findings: list        # list[Finding]
    llm_findings: list        # list[LLMFinding]
    exploit_results: list     # list[ExploitResult]
    report_path: str
    config: dict              # {run_semgrep, run_exploit, model, output, i_own_target}
