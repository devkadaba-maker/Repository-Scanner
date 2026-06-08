"""Report generation node — compiles all findings into audit_report.md."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from auditagent.utils import DEFAULT_MODEL


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
}


def _exploit_block(exploit_results: list[dict], finding_id: str) -> str:
    for er in exploit_results:
        if er.get("finding_id") == finding_id:
            verdict = er.get("verdict", "Inconclusive")
            executed = er.get("executed", False)
            evidence = er.get("evidence", "")
            impact = er.get("impact", "")
            poc = er.get("poc", "")
            lines = [
                "",
                "**Exploitation Validation**",
                f"- Verdict  : **{verdict}**",
                f"- Executed : {'Yes' if executed else 'No (app did not start or exploit skipped)'}",
            ]
            if impact:
                lines.append(f"- Impact   : {impact}")
            if evidence:
                lines += [
                    "",
                    "<details><summary>Evidence</summary>",
                    "",
                    "```",
                    evidence[:1500],
                    "```",
                    "</details>",
                ]
            if poc:
                lines += [
                    "",
                    "<details><summary>PoC script</summary>",
                    "",
                    "```python",
                    poc[:2000],
                    "```",
                    "</details>",
                ]
            return "\n".join(lines)
    return ""


def _red_team_section(state: dict) -> list[str]:
    """Builds the Red Team section (Attack Plans, Impact Assessments, Attack
    Chains). Returns [] when the subgraph didn't run, leaving existing reports
    byte-for-byte unaffected."""
    attack_plans: list[dict] = state.get("attack_plans", [])
    impact_assessments: list[dict] = state.get("impact_assessments", [])
    attack_chains: list[dict] = state.get("attack_chains", [])

    if not attack_plans and not impact_assessments and not attack_chains:
        return []

    lines: list[str] = ["", "---", "", "## 🎯 Red Team", ""]

    if attack_plans:
        lines += ["### Attack Plans", ""]
        for plan in attack_plans:
            gate = "✅ Cleared for execution" if plan.get("safe_to_execute") else "⛔ Skipped (unsafe to execute)"
            lines += [
                f"#### `{plan.get('finding_id', '')}` — {gate}",
                "",
                f"**Reasoning**  ",
                plan.get("reasoning", "_not provided_"),
                "",
            ]
            if plan.get("safe_to_execute"):
                lines += [
                    f"**Target**: {plan.get('target_description', '_not provided_')}",
                    "",
                    "**Steps**",
                    "",
                ]
                lines += [f"{i + 1}. {step}" for i, step in enumerate(plan.get("steps", []))] or ["_not provided_"]
                lines += [
                    "",
                    f"**Expected outcome**: {plan.get('expected_outcome', '_not provided_')}",
                    "",
                ]
            lines.append("")

    if impact_assessments:
        lines += [
            "### Impact Assessments",
            "",
            "| Finding | Confirmed Severity | Data at Risk | Systems at Risk | Users at Risk |",
            "|---------|--------------------|--------------|-----------------|----------------|",
        ]
        for ia in impact_assessments:
            sev = ia.get("severity", "")
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(
                f"| `{ia.get('finding_id', '')}` | {emoji} {sev} "
                f"| {ia.get('data_at_risk', '_n/a_')} "
                f"| {ia.get('systems_at_risk', '_n/a_')} "
                f"| {ia.get('users_at_risk', '_n/a_')} |"
            )
        lines.append("")
        for ia in impact_assessments:
            if ia.get("summary"):
                lines += [
                    f"**`{ia.get('finding_id', '')}` — Impact Summary**  ",
                    ia["summary"],
                    "",
                ]

    if attack_chains:
        lines += ["### Attack Chains", ""]
        for i, chain in enumerate(attack_chains, start=1):
            sev = chain.get("combined_severity", "")
            emoji = SEVERITY_EMOJI.get(sev, "")
            ids = ", ".join(f"`{fid}`" for fid in chain.get("finding_ids", []))
            lines += [
                f"#### Chain {i} — {emoji} Combined severity: {sev}",
                "",
                f"**Findings chained**: {ids}",
                "",
                "**Attack Story**  ",
                chain.get("narrative", "_not provided_"),
                "",
                f"**Combined Impact**: {chain.get('combined_impact', '_not provided_')}",
                "",
            ]

    return lines


def report_node(state: dict) -> dict:
    project_path = state["project_path"]
    config = state.get("config", {})
    output_name = config.get("output", "audit_report.md")

    # Validate output_name has no path separators to prevent traversal
    if os.sep in output_name or "/" in output_name or "\\" in output_name:
        raise ValueError(
            f"--output must be a plain filename (no path separators): {output_name!r}"
        )

    llm_findings: list[dict] = state.get("llm_findings", [])
    exploit_results: list[dict] = state.get("exploit_results", [])
    tech_stack: dict = state.get("tech_stack", {})

    # Counts
    confirmed = [f for f in llm_findings if f.get("confirmed")]
    by_severity: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
    for f in confirmed:
        sev = f.get("severity", "Low")
        by_severity.setdefault(sev, []).append(f)

    n_exploitable = sum(1 for f in confirmed if f.get("exploitable"))
    n_exploited = sum(1 for er in exploit_results if er.get("verdict") == "Exploitable")

    lines = []

    # Header
    lines += [
        "# Security Audit Report",
        "",
        f"**Project** : `{project_path}`  ",
        f"**Date**    : {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        f"**Language** : {', '.join(tech_stack.get('languages', [])) or tech_stack.get('language', 'unknown')}  ",
        f"**Framework**: {tech_stack.get('framework', 'unknown')}  ",
        f"**Model**   : {config.get('model', DEFAULT_MODEL)}  ",
        "",
    ]

    # Executive summary table
    lines += [
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in SEVERITY_ORDER:
        cnt = len(by_severity.get(sev, []))
        emoji = SEVERITY_EMOJI.get(sev, "")
        lines.append(f"| {emoji} {sev} | {cnt} |")

    lines += [
        f"| **Total confirmed** | **{len(confirmed)}** |",
        f"| Exploitable (LLM) | {n_exploitable} |",
    ]
    if exploit_results:
        lines.append(f"| Exploited (PoC verified) | {n_exploited} |")

    lines += ["", "---", ""]

    if not confirmed:
        lines += ["## No Confirmed Findings", "", "> No vulnerabilities were confirmed by the LLM analysis.", ""]
    else:
        lines += ["## Findings by Severity", ""]
        for sev in SEVERITY_ORDER:
            findings_in_sev = by_severity.get(sev, [])
            if not findings_in_sev:
                continue
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines += [f"### {emoji} {sev}", ""]

            for lf in findings_in_sev:
                f: dict = lf["finding"]
                fid = f["id"]
                loc = f"{f['file']}:{f['line']}" if f.get("file") else "(dependency)"
                lines += [
                    f"#### {f['issue']}",
                    "",
                    "| Field | Value |",
                    "|-------|-------|",
                    f"| **ID** | `{fid}` |",
                    f"| **Location** | `{loc}` |",
                    f"| **Source** | {f['source']} |",
                    f"| **Severity** | {sev} |",
                    f"| **Exploitable** | {'Yes' if lf.get('exploitable') else 'No'} |",
                    "",
                    "**Attack Vector**  ",
                    lf.get("attack_vector", "_not provided_"),
                    "",
                    "**Explanation**  ",
                    lf.get("explanation", "_not provided_"),
                    "",
                    "**Suggested Fix**  ",
                    lf.get("fix", "_not provided_"),
                    "",
                ]

                snippet = f.get("code_snippet", "")
                if snippet:
                    lines += [
                        "<details><summary>Code snippet</summary>",
                        "",
                        "```python",
                        snippet,
                        "```",
                        "",
                        "</details>",
                        "",
                    ]

                meta = f.get("metadata", {})
                if meta.get("vuln_id") or meta.get("aliases"):
                    refs = ", ".join(filter(None, [meta.get("vuln_id")] + meta.get("aliases", [])))
                    lines += [f"**References**: {refs}", ""]
                if meta.get("fix_versions"):
                    lines += [f"**Fix version(s)**: `{', '.join(meta['fix_versions'])}`", ""]

                expl = _exploit_block(exploit_results, fid)
                if expl:
                    lines.append(expl)

                lines += ["---", ""]

    rt_section = _red_team_section(state)
    if rt_section:
        lines += rt_section

    # Footer
    lines += [
        "",
        "*Report generated by [security-audit-agent](https://github.com/security-audit-agent).*",
        "*For ethical use only — on systems you own or are authorised to test.*",
    ]

    report_content = "\n".join(lines)

    # Write to CWD, not inside the audited project directory
    report_path = str(Path.cwd() / output_name)
    Path(report_path).write_text(report_content, encoding="utf-8")

    return {**state, "report_path": report_path}
