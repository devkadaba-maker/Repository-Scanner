#!/usr/bin/env python3
"""
audit.py — Ethical security audit agent for web & application projects (any language).

Usage:
    python audit.py <path-to-project> [--no-semgrep] [--exploit]
                    [--i-own-this-target] [--red-team] [--chain-findings]
                    [--model MODEL] [--output FILE]

The agent runs a LangGraph pipeline:
    recon → static_analysis → dependency_audit → [route]
        ├─ no findings → report
        └─ findings   → llm_analysis → [route_exploit]
                            ├─ --exploit & exploitable → exploitation → [route_red_team]
                            │                                 ├─ --red-team → red_team → report
                            │                                 └─ else        → report
                            └─ else → report
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from auditagent.state import AuditState
from auditagent.utils import DEFAULT_MODEL
from auditagent.nodes.recon import recon_node
from auditagent.nodes.static_analysis import static_analysis_node
from auditagent.nodes.dependency_audit import dependency_audit_node
from auditagent.nodes.llm_analysis import llm_analysis_node
from auditagent.nodes.exploitation import exploitation_node
from auditagent.nodes.red_team import red_team_node, route_red_team
from auditagent.nodes.report import report_node

console = Console()


# ---------------------------------------------------------------------------
# Routing functions
# ---------------------------------------------------------------------------

def route_findings(state: dict) -> str:
    """Skip LLM analysis if there are no findings."""
    if not state.get("raw_findings"):
        return "report"
    return "llm_analysis"


def route_exploit(state: dict) -> str:
    """Run exploitation node only when enabled and exploitable findings exist."""
    config = state.get("config", {})
    if config.get("run_exploit") and any(
        f.get("exploitable") and f.get("confirmed")
        for f in state.get("llm_findings", [])
    ):
        return "exploitation"
    return "report"


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def build_graph() -> StateGraph:
    graph = StateGraph(dict)

    graph.add_node("recon", recon_node)
    graph.add_node("static_analysis", static_analysis_node)
    graph.add_node("dependency_audit", dependency_audit_node)
    graph.add_node("llm_analysis", llm_analysis_node)
    graph.add_node("exploitation", exploitation_node)
    graph.add_node("red_team", red_team_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("recon")
    graph.add_edge("recon", "static_analysis")
    graph.add_edge("static_analysis", "dependency_audit")
    graph.add_conditional_edges(
        "dependency_audit",
        route_findings,
        {"report": "report", "llm_analysis": "llm_analysis"},
    )
    graph.add_conditional_edges(
        "llm_analysis",
        route_exploit,
        {"exploitation": "exploitation", "report": "report"},
    )
    graph.add_conditional_edges(
        "exploitation",
        route_red_team,
        {"red_team": "red_team", "report": "report"},
    )
    graph.add_edge("red_team", "report")
    graph.add_edge("report", END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Rich summary table
# ---------------------------------------------------------------------------

def print_summary(final_state: dict) -> None:
    llm_findings = final_state.get("llm_findings", [])
    exploit_results = final_state.get("exploit_results", [])
    report_path = final_state.get("report_path", "")
    tech_stack = final_state.get("tech_stack", {})

    console.rule("[bold blue]Audit Complete[/bold blue]")

    # Severity breakdown
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for lf in llm_findings:
        if lf.get("confirmed"):
            sev = lf.get("severity", "Low")
            counts[sev] = counts.get(sev, 0) + 1

    n_exploitable = sum(1 for f in llm_findings if f.get("exploitable") and f.get("confirmed"))
    n_poc_verified = sum(1 for er in exploit_results if er.get("verdict") == "Exploitable")

    table = Table(title="Findings Summary", show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("🔴 Critical", str(counts["Critical"]))
    table.add_row("🟠 High",     str(counts["High"]))
    table.add_row("🟡 Medium",   str(counts["Medium"]))
    table.add_row("🟢 Low",      str(counts["Low"]))
    table.add_row("──────────", "────")
    table.add_row("Total confirmed", str(sum(counts.values())))
    table.add_row("Exploitable (LLM)", str(n_exploitable))
    if exploit_results:
        table.add_row("PoC verified", str(n_poc_verified))

    console.print(table)

    # Details
    info_table = Table(show_header=False, box=None, padding=(0, 1))
    info_table.add_column("Key", style="dim")
    info_table.add_column("Value")
    info_table.add_row("Language", ", ".join(tech_stack.get("languages", [])) or tech_stack.get("language", "unknown"))
    info_table.add_row("Framework", tech_stack.get("framework", "unknown"))
    info_table.add_row("Source files", str(tech_stack.get("source_file_count", 0)))
    if report_path:
        info_table.add_row("Report", report_path)
    console.print(info_table)
    console.print()


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Ethical security audit agent for web & application projects (any language).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("project_path", help="Path to the project to audit (any language).")
    parser.add_argument(
        "--no-semgrep",
        action="store_true",
        help="Skip semgrep (faster; use on first run).",
    )
    parser.add_argument(
        "--exploit",
        action="store_true",
        help="Run safe exploitation / PoC validation (requires --i-own-this-target).",
    )
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        dest="i_own_target",
        help="Acknowledge that you own or are authorised to test this target.",
    )
    parser.add_argument(
        "--red-team",
        action="store_true",
        dest="red_team",
        help="Run the red-team subgraph after exploitation: plan → generate PoC → "
             "execute (sandboxed) → assess impact (requires --exploit and --i-own-this-target).",
    )
    parser.add_argument(
        "--chain-findings",
        action="store_true",
        dest="chain_findings",
        help="Within the red-team subgraph, analyse exploited findings for multi-step "
             "attack chains (requires --red-team).",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"OpenRouter model ID (default: {DEFAULT_MODEL}).",
    )
    parser.add_argument(
        "--output",
        default="audit_report.md",
        help="Output filename for the report (default: audit_report.md).",
    )
    args = parser.parse_args()

    # Validate project path
    project_path = Path(args.project_path).expanduser().resolve()
    if not project_path.exists():
        console.print(f"[red]Error:[/red] Project path does not exist: {project_path}")
        sys.exit(1)

    # Validate API key
    if not os.environ.get("OPENROUTER_API_KEY"):
        console.print(
            "[red]Error:[/red] OPENROUTER_API_KEY is not set.\n"
            "Copy .env.example → .env and add your key, or export it in your shell."
        )
        sys.exit(1)

    # Exploitation safety check
    if args.exploit and not args.i_own_target:
        console.print(
            "[red]Error:[/red] --exploit requires --i-own-this-target.\n"
            "Pass both flags to confirm you own / are authorised to test this target."
        )
        sys.exit(1)

    # Red-team flags rely on the exploitation gate — warn (don't block) on misuse
    if args.red_team and not (args.exploit and args.i_own_target):
        console.print(
            "[yellow]Warning:[/yellow] --red-team has no effect without --exploit and "
            "--i-own-this-target — the subgraph will be skipped."
        )
    if args.chain_findings and not args.red_team:
        console.print(
            "[yellow]Warning:[/yellow] --chain-findings has no effect without --red-team."
        )

    config = {
        "run_semgrep": not args.no_semgrep,
        "run_exploit": args.exploit,
        "i_own_target": args.i_own_target,
        "red_team": args.red_team,
        "chain_findings": args.chain_findings,
        "model": args.model,
        "output": args.output,
    }

    initial_state: AuditState = {
        "project_path": str(project_path),
        "tech_stack": {},
        "source_files": [],
        "dependencies": [],
        "raw_findings": [],
        "llm_findings": [],
        "exploit_results": [],
        "attack_plans": [],
        "poc_scripts": [],
        "impact_assessments": [],
        "attack_chains": [],
        "report_path": "",
        "config": config,
    }

    graph = build_graph()

    console.rule(f"[bold green]Security Audit[/bold green] — {project_path.name}")

    node_labels = {
        "recon": "Recon (tech stack, files, deps)",
        "static_analysis": "Static analysis (bandit" + ("+ semgrep)" if config["run_semgrep"] else ")"),
        "dependency_audit": "Dependency audit (pip-audit)",
        "llm_analysis": "LLM analysis (confirming findings)",
        "exploitation": "Safe exploitation (PoC validation)",
        "red_team": "Red team (plan → PoC → execute → assess → chain)",
        "report": "Report generation",
    }

    final_state = initial_state
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=None)

        for step in graph.stream(initial_state):
            node_name = next(iter(step))
            if node_name not in node_labels:
                # LangGraph may emit internal metadata events; skip them
                continue
            label = node_labels[node_name]
            progress.update(task, description=f"[cyan]{label}[/cyan]")
            final_state = step[node_name]

    print_summary(final_state)

    # Exit with a non-zero code if critical/high findings confirmed
    has_critical = any(
        f.get("confirmed") and f.get("severity") in ("Critical", "High")
        for f in final_state.get("llm_findings", [])
    )
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
