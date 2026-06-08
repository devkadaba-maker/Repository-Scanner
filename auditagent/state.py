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
    """Result of the safe local exploitation node.

    Also reused (and appended to) by the red-team subgraph's execute_poc node —
    entries it adds carry an extra "source": "red_team" key so the report can
    tell the two apart.
    """
    finding_id: str
    poc: str                 # the PoC script / curl command generated
    executed: bool           # whether the PoC was actually run
    verdict: str             # "Exploitable" | "Not exploitable" | "Inconclusive"
    evidence: str            # captured request/response or error output
    impact: str              # brief impact statement from LLM


class AttackPlan(TypedDict):
    """Red-team subgraph: LLM-authored plan for a confirmed, exploitable finding.

    `safe_to_execute` is the execution gate — generate_poc/execute_poc skip the
    finding silently whenever it is False.
    """
    finding_id: str
    safe_to_execute: bool    # gate — must be True before any PoC is generated/run
    reasoning: str           # why this is / isn't safe to execute locally
    target_description: str  # what a PoC would target (e.g. "GET /login on the sandbox")
    steps: list              # list[str] — ordered, concrete attack steps
    expected_outcome: str    # what a successful PoC run would observe


class PoCScript(TypedDict):
    """Red-team subgraph: generated PoC for a plan cleared as safe to execute."""
    finding_id: str
    code: str                # self-contained, non-destructive Python PoC source


class ImpactAssessment(TypedDict):
    """Red-team subgraph: concrete, specific impact write-up from execution evidence."""
    finding_id: str
    summary: str             # concrete 2-4 sentence impact summary
    data_at_risk: str        # specific data / fields / secrets exposed
    systems_at_risk: str     # specific systems / services / components affected
    users_at_risk: str       # specific user populations / roles affected
    severity: str            # Critical | High | Medium | Low (LLM-confirmed from evidence)


class AttackChain(TypedDict):
    """Red-team subgraph: a multi-finding chain identified across exploited findings."""
    finding_ids: list        # list[str], len >= 2, in chain order
    narrative: str           # step-by-step attacker story ("attack story")
    combined_severity: str   # Critical | High | Medium | Low — the chain's own rating
    combined_impact: str     # concrete statement of the combined outcome


class AuditState(TypedDict):
    """Full mutable state carried through the LangGraph pipeline."""
    project_path: str
    tech_stack: dict          # {framework, entrypoint, python_version, …}
    source_files: list        # list of str paths
    dependencies: list        # list of str "package==version" entries
    raw_findings: list        # list[Finding]
    llm_findings: list        # list[LLMFinding]
    exploit_results: list     # list[ExploitResult] — extended in place by the red-team subgraph
    # --- Red-team subgraph state (opt-in via --red-team / --chain-findings) ---
    attack_plans: list        # list[AttackPlan]
    poc_scripts: list         # list[PoCScript]
    impact_assessments: list  # list[ImpactAssessment]
    attack_chains: list       # list[AttackChain]
    report_path: str
    config: dict              # {run_semgrep, run_exploit, red_team, chain_findings, model, output, i_own_target}
