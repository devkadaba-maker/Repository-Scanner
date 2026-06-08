"""Red-team subgraph — plan, generate, execute, and assess PoC exploits, then
chain the confirmed exploits into multi-step attack narratives.

This is a self-contained LangGraph subgraph (`plan_attack -> generate_poc ->
execute_poc -> capture_evidence -> chain_findings`) wrapped behind a single
`red_team_node`/`route_red_team` pair that plugs into the existing pipeline
immediately after the `exploitation` node — entirely opt-in via --red-team
(and --chain-findings for the final chaining step).

SAFETY GUARDRAILS
-----------------
- Requires the SAME flags as the existing `exploitation` node: --exploit AND
  --i-own-this-target. Without both, this subgraph is a silent no-op (and the
  main graph never routes here, since it only follows `exploitation`).
- `plan_attack` is the execution gate: every finding gets an LLM-authored
  attack plan with an explicit `safe_to_execute` verdict, and anything marked
  unsafe is skipped SILENTLY by every downstream node — no PoC is generated,
  written, or run for it.
- PoCs run against a fresh, throwaway COPY of the project under /tmp (never
  the real project directory), with a hard 30-second timeout, a stripped
  environment (no secrets/API keys forwarded), and are wrapped in Docker with
  `--network=none` (+ cpu/memory/pids limits) whenever Docker AND a usable
  local image are available — falling back to a restricted subprocess
  otherwise. Sandboxes are always removed in `finally`.
- Generated PoCs are instructed to target 127.0.0.1 only, to be read-only or
  single-benign-write, and to finish well within the time budget.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END

from auditagent.llm import get_llm
from auditagent.utils import DEFAULT_MODEL


MAX_WORKERS = 5            # lighter than llm_analysis — these are heavier multi-step calls
EXEC_TIMEOUT = 30          # hard PoC execution timeout (seconds), per the safety spec
DOCKER_IMAGE = "python:3.11-slim"

# Env keys forwarded into the PoC execution environment — secrets are NOT forwarded
_SAFE_ENV_KEYS = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "USER", "LOGNAME", "SHELL"}

_IGNORE_PATTERNS = shutil.ignore_patterns(
    ".venv", "venv", ".git", "__pycache__", "node_modules", "*.pyc", "*.pyo"
)


# ---------------------------------------------------------------------------
# Small helpers shared by all the LLM steps
# ---------------------------------------------------------------------------

def _parse_json(raw: str) -> dict:
    """Extract a JSON object from LLM output, stripping markdown fences if present."""
    raw = raw.strip()
    match = re.search(r"```(?:json)?\s*\n?([\s\S]+?)\n?\s*```", raw)
    if match:
        raw = match.group(1).strip()
    return json.loads(raw)


def _strip_code_fences(raw: str) -> str:
    """LLMs sometimes wrap "no markdown" code in ```python fences anyway —
    strip them so the PoC doesn't fail with SyntaxError before it even runs."""
    raw = raw.strip()
    match = re.search(r"```(?:python|py)?\s*\n?([\s\S]+?)\n?\s*```", raw)
    return match.group(1).strip() if match else raw


def _extract_verdict(output: str) -> str:
    for line in output.splitlines():
        upper = line.upper()
        if "VERDICT:" in upper:
            if "NOT EXPLOITABLE" in upper:
                return "Not exploitable"
            if "EXPLOITABLE" in upper:
                return "Exploitable"
            return "Inconclusive"
    return "Inconclusive"


def _extract_impact_line(output: str) -> str:
    for line in output.splitlines():
        if line.upper().startswith("IMPACT:"):
            return line.split(":", 1)[1].strip()
    return ""


def _is_red_team_ready(config: dict) -> bool:
    """Same gate as the existing exploitation node — both flags required."""
    return bool(config.get("run_exploit") and config.get("i_own_target"))


# ---------------------------------------------------------------------------
# Node 1 — plan_attack
# ---------------------------------------------------------------------------

_PLAN_SYSTEM = """\
You are an expert red-team security engineer performing an authorised, ethical \
penetration test against a system the requester owns and has explicitly approved \
for live local testing. You will be shown one CONFIRMED, exploitable vulnerability \
finding.

Your job is to produce a structured attack plan AND — most importantly — to gate \
whether it is safe to actually execute anything against a local sandbox. Mark \
"safe_to_execute": false whenever execution could plausibly:
- modify, delete, or exfiltrate real data, even partially or temporarily,
- disrupt a running service (DoS, resource exhaustion, crashes, hangs),
- require reaching anything other than 127.0.0.1 / localhost,
- require real credentials, production systems, or any irreversible action,
- take meaningfully longer than a few seconds to demonstrate.

Only mark "safe_to_execute": true for low-risk, tightly-bounded, mostly read-only \
demonstrations against a local sandbox copy (e.g. a benign reflected payload, a \
boolean/time-based read-only probe, a path-traversal read of a known-benign file, \
an auth-bypass probe that only reads non-sensitive data, a hardcoded-secret check \
that just prints whether the secret is reachable). When genuinely unsure, choose \
false and explain why in "reasoning"."""

_PLAN_HUMAN = """\
## Confirmed finding
- Issue        : {issue}
- File         : {file}
- Line         : {line}
- Severity     : {severity}
- Attack vector: {attack_vector}
- Explanation  : {explanation}

## Code snippet
```
{code_snippet}
```

---
Return ONLY a JSON object (no markdown fence, no extra text) with these keys:
{{
  "safe_to_execute": true|false,
  "reasoning": "<concrete reason this is / isn't safe to run locally>",
  "target_description": "<precisely what a PoC would target, e.g. 'GET /login on the local sandbox copy'>",
  "steps": ["<ordered, concrete attack step>", "..."],
  "expected_outcome": "<what a successful PoC run would concretely observe>"
}}"""

_plan_prompt = ChatPromptTemplate.from_messages([
    ("system", _PLAN_SYSTEM),
    ("human", _PLAN_HUMAN),
])

_str_parser = StrOutputParser()


def _plan_attack_for_finding(llm_finding: dict, model: str) -> dict:
    f = llm_finding["finding"]
    llm = get_llm(model=model, temperature=0.1)
    chain = _plan_prompt | llm | _str_parser

    raw = chain.invoke({
        "issue": f["issue"],
        "file": f["file"],
        "line": f["line"],
        "severity": llm_finding.get("severity", f.get("severity", "")),
        "attack_vector": llm_finding.get("attack_vector", ""),
        "explanation": llm_finding.get("explanation", ""),
        "code_snippet": f.get("code_snippet") or "(no snippet available)",
    })
    data = _parse_json(raw)
    return {
        "finding_id": f["id"],
        "safe_to_execute": bool(data.get("safe_to_execute", False)),
        "reasoning": data.get("reasoning", ""),
        "target_description": data.get("target_description", ""),
        "steps": [str(s) for s in data.get("steps", [])],
        "expected_outcome": data.get("expected_outcome", ""),
    }


def plan_attack_node(state: dict) -> dict:
    config = state.get("config", {})
    if not _is_red_team_ready(config):
        return {**state, "attack_plans": []}

    llm_findings: list[dict] = state.get("llm_findings", [])
    candidates = [f for f in llm_findings if f.get("confirmed") and f.get("exploitable")]
    if not candidates:
        print("[red-team] No confirmed-exploitable findings to plan against — skipping.")
        return {**state, "attack_plans": []}

    model = config.get("model", DEFAULT_MODEL)
    print(f"\n[red-team] plan_attack — reasoning about {len(candidates)} finding(s)...")

    plans: list[dict] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_plan_attack_for_finding, f, model): f for f in candidates}
        for future in as_completed(futures):
            orig = futures[future]
            fid = orig["finding"]["id"]
            try:
                plan = future.result()
            except Exception as exc:
                plan = {
                    "finding_id": fid,
                    "safe_to_execute": False,
                    "reasoning": f"Planning failed — defaulting to unsafe: {exc}",
                    "target_description": "",
                    "steps": [],
                    "expected_outcome": "",
                }
            gate = "cleared" if plan["safe_to_execute"] else "SKIPPED (unsafe)"
            print(f"  [red-team] {fid} → {gate}")
            plans.append(plan)

    return {**state, "attack_plans": plans}


# ---------------------------------------------------------------------------
# Node 2 — generate_poc
# ---------------------------------------------------------------------------

_REDTEAM_POC_SYSTEM = """\
You are an expert penetration tester producing a NON-DESTRUCTIVE, self-contained \
proof-of-concept for an authorised red-team engagement against a target the \
requester owns. The PoC will run inside a locked-down sandbox: no network access \
beyond 127.0.0.1, a hard 30-second timeout, a throwaway working directory, and a \
stripped environment with no credentials.

Hard rules:
- Target 127.0.0.1 only. If your plan needs a running network service and none \
  is guaranteed to be running, launch a minimal local instance yourself (bound \
  to 127.0.0.1 on a free port you choose) at the top of the script — staying \
  well within the 30-second budget — or, if that isn't practical, operate \
  directly against the sandboxed project copy's source/config/files instead.
- Read-only or single-benign-write operations only. No deletion or mutation of \
  real data, no destructive payloads, no resource-exhaustion / DoS patterns.
- Must finish comfortably within 30 seconds.
- stdlib + httpx only (already installed). No other third-party packages, no \
  package installation.
- Clean up any files you create before exiting.
- Print a clear "VERDICT: Exploitable" / "VERDICT: Not exploitable" / \
  "VERDICT: Inconclusive" line, and a one-line "IMPACT: <concrete statement>" line."""

_REDTEAM_POC_HUMAN = """\
## Sandbox environment
- A throwaway, read-write COPY of the project lives at: {{project_dir}}
  (relative to the script's working directory — use it, never the original project)
- No live instance of the target is guaranteed to be running.

## Attack plan
- Target            : {target_description}
- Steps:
{steps}
- Expected outcome  : {expected_outcome}

## Underlying finding
- Issue : {issue}
- File  : {file}
- Line  : {line}

## Code snippet
```
{code_snippet}
```

Produce ONLY a Python snippet (no markdown fences) implementing this plan."""

_redteam_poc_prompt = ChatPromptTemplate.from_messages([
    ("system", _REDTEAM_POC_SYSTEM),
    ("human", _REDTEAM_POC_HUMAN),
])


def _generate_poc_for_plan(plan: dict, llm_finding: dict, model: str) -> str:
    f = llm_finding["finding"]
    llm = get_llm(model=model, temperature=0.2)
    chain = _redteam_poc_prompt | llm | _str_parser

    steps = plan.get("steps") or []
    steps_block = "\n".join(f"  {i + 1}. {s}" for i, s in enumerate(steps)) or "  (none provided)"

    raw = chain.invoke({
        "target_description": plan.get("target_description", ""),
        "steps": steps_block,
        "expected_outcome": plan.get("expected_outcome", ""),
        "issue": f["issue"],
        "file": f["file"],
        "line": f["line"],
        "code_snippet": f.get("code_snippet") or "(no snippet available)",
    })
    return _strip_code_fences(raw)


def generate_poc_node(state: dict) -> dict:
    config = state.get("config", {})
    if not _is_red_team_ready(config):
        return {**state, "poc_scripts": []}

    plans: list[dict] = state.get("attack_plans", [])
    safe_plans = [p for p in plans if p.get("safe_to_execute")]
    skipped = len(plans) - len(safe_plans)
    if skipped:
        print(f"[red-team] generate_poc — skipping {skipped} plan(s) marked unsafe to execute.")
    if not safe_plans:
        return {**state, "poc_scripts": []}

    llm_by_id = {lf["finding"]["id"]: lf for lf in state.get("llm_findings", [])}
    model = config.get("model", DEFAULT_MODEL)
    print(f"[red-team] generate_poc — writing {len(safe_plans)} PoC(s)...")

    scripts: list[dict] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {}
        for plan in safe_plans:
            lf = llm_by_id.get(plan["finding_id"])
            if not lf:
                continue
            futures[pool.submit(_generate_poc_for_plan, plan, lf, model)] = plan

        for future in as_completed(futures):
            plan = futures[future]
            fid = plan["finding_id"]
            try:
                code = future.result()
                scripts.append({"finding_id": fid, "code": code})
                print(f"  [red-team] PoC ready for {fid}")
            except Exception as exc:
                print(f"  [red-team] PoC generation failed for {fid}: {exc}")

    return {**state, "poc_scripts": scripts}


# ---------------------------------------------------------------------------
# Node 3 — execute_poc
# ---------------------------------------------------------------------------

def _docker_runnable() -> bool:
    """True only if `docker` works AND the image we'd run is already present
    locally — we never trigger a network pull from inside the audit run."""
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=True)
        subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE], capture_output=True, timeout=5, check=True)
        return True
    except Exception:
        return False


def _run_sandboxed(work_dir: str, use_docker: bool) -> tuple[str, bool]:
    """Run ./poc.py inside `work_dir`. Returns (captured stdout+stderr, executed)."""
    if use_docker:
        cmd = [
            "docker", "run", "--rm",
            "--network=none",
            "--cpus=1", "--memory=256m", "--pids-limit=128",
            "-v", f"{work_dir}:/sandbox",
            "-w", "/sandbox",
            DOCKER_IMAGE, "python", "poc.py",
        ]
        env = None
    else:
        cmd = [sys.executable, "poc.py"]
        env = {k: v for k, v in os.environ.items() if k in _SAFE_ENV_KEYS}

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=EXEC_TIMEOUT, env=env, cwd=work_dir,
        )
        return (result.stdout + result.stderr).strip(), True
    except subprocess.TimeoutExpired:
        return "[PoC timed out after 30s — terminated]", True
    except Exception as exc:
        return f"[PoC execution error: {exc}]", False


def _execute_one_poc(project_path: str, code: str, use_docker: bool) -> str:
    """Build a fresh throwaway sandbox under /tmp, run the PoC inside it, and
    always remove it — never touches the real project directory."""
    sandbox_root = tempfile.mkdtemp(prefix="redteam_poc_", dir=tempfile.gettempdir())
    try:
        project_copy = os.path.join(sandbox_root, "project")
        try:
            shutil.copytree(project_path, project_copy, dirs_exist_ok=True, ignore=_IGNORE_PATTERNS)
        except Exception:
            os.makedirs(project_copy, exist_ok=True)

        script = (
            code
            .replace("{project_dir}", "./project")
            .replace("{host}", "127.0.0.1")
        )
        Path(sandbox_root, "poc.py").write_text(script)

        output, executed = _run_sandboxed(sandbox_root, use_docker)
        return output if executed else f"[execution skipped: {output}]"
    finally:
        shutil.rmtree(sandbox_root, ignore_errors=True)


def execute_poc_node(state: dict) -> dict:
    config = state.get("config", {})
    if not _is_red_team_ready(config):
        return {**state}

    scripts: list[dict] = state.get("poc_scripts", [])
    if not scripts:
        return {**state}

    project_path = state["project_path"]
    use_docker = _docker_runnable()
    isolation = "Docker (--network=none, no real image pulls)" if use_docker else "restricted subprocess"
    print(
        f"\n[red-team] execute_poc — running {len(scripts)} PoC(s) "
        f"[{isolation}, {EXEC_TIMEOUT}s hard timeout, throwaway /tmp sandbox per run]\n"
    )

    new_results: list[dict] = []
    for script in scripts:
        fid = script["finding_id"]
        code = script["code"]
        print(f"  [red-team] running PoC for {fid}...")
        output = _execute_one_poc(project_path, code, use_docker)
        verdict = _extract_verdict(output)
        impact_line = _extract_impact_line(output)
        new_results.append({
            "finding_id": fid,
            "poc": code,
            "executed": True,
            "verdict": verdict,
            "evidence": output[:2000],
            "impact": impact_line,   # capture_evidence overwrites this with a fuller summary
            "source": "red_team",
        })
        print(f"  [red-team] {fid} → {verdict}")

    existing = state.get("exploit_results", [])
    return {**state, "exploit_results": existing + new_results}


# ---------------------------------------------------------------------------
# Node 4 — capture_evidence
# ---------------------------------------------------------------------------

_EVIDENCE_SYSTEM = """\
You are a security analyst writing the impact-assessment section of a \
penetration-test report for executive and engineering stakeholders. Be concrete \
and specific: name the actual data, fields, systems, services, and user \
populations placed at risk by THIS finding, grounded in the captured execution \
evidence. Do not use vague hedging language ("could potentially", "may allow", \
"might expose") when the evidence already demonstrates the outcome — state \
plainly what was observed and what it means for the organisation. If the \
evidence is inconclusive, say so plainly and state exactly what would need to \
be true for exploitation to succeed."""

_EVIDENCE_HUMAN = """\
## Finding
- Issue          : {issue}
- Attack vector  : {attack_vector}
- PoC target     : {target_description}
- Execution verdict: {verdict}

## Captured execution evidence (stdout + stderr)
```
{evidence}
```

---
Return ONLY a JSON object (no markdown fence, no extra text) with these keys:
{{
  "summary": "<2-4 sentence concrete impact summary, grounded in the evidence>",
  "data_at_risk": "<specific data / fields / secrets exposed or at risk>",
  "systems_at_risk": "<specific systems, services, or components affected>",
  "users_at_risk": "<specific user populations or roles affected>",
  "severity_confirmation": "Critical"|"High"|"Medium"|"Low"
}}"""

_evidence_prompt = ChatPromptTemplate.from_messages([
    ("system", _EVIDENCE_SYSTEM),
    ("human", _EVIDENCE_HUMAN),
])


def _capture_evidence_for_result(exploit_result: dict, llm_finding: dict, plan: dict | None, model: str) -> dict:
    f = llm_finding["finding"]
    llm = get_llm(model=model, temperature=0.1)
    chain = _evidence_prompt | llm | _str_parser

    raw = chain.invoke({
        "issue": f["issue"],
        "attack_vector": llm_finding.get("attack_vector", ""),
        "target_description": (plan or {}).get("target_description", ""),
        "verdict": exploit_result.get("verdict", "Inconclusive"),
        "evidence": exploit_result.get("evidence") or "(no output captured)",
    })
    data = _parse_json(raw)
    return {
        "finding_id": f["id"],
        "summary": data.get("summary", ""),
        "data_at_risk": data.get("data_at_risk", ""),
        "systems_at_risk": data.get("systems_at_risk", ""),
        "users_at_risk": data.get("users_at_risk", ""),
        "severity": data.get("severity_confirmation", llm_finding.get("severity", "")),
    }


def capture_evidence_node(state: dict) -> dict:
    config = state.get("config", {})
    if not _is_red_team_ready(config):
        return {**state, "impact_assessments": []}

    exploit_results: list[dict] = state.get("exploit_results", [])
    red_team_results = [er for er in exploit_results if er.get("source") == "red_team"]
    if not red_team_results:
        return {**state, "impact_assessments": []}

    llm_by_id = {lf["finding"]["id"]: lf for lf in state.get("llm_findings", [])}
    plan_by_id = {p["finding_id"]: p for p in state.get("attack_plans", [])}
    model = config.get("model", DEFAULT_MODEL)
    print(f"\n[red-team] capture_evidence — assessing impact of {len(red_team_results)} executed PoC(s)...")

    assessments: list[dict] = []
    updated_results = list(exploit_results)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {}
        for er in red_team_results:
            lf = llm_by_id.get(er["finding_id"])
            if not lf:
                continue
            futures[pool.submit(_capture_evidence_for_result, er, lf, plan_by_id.get(er["finding_id"]), model)] = er

        for future in as_completed(futures):
            er = futures[future]
            fid = er["finding_id"]
            try:
                assessment = future.result()
            except Exception as exc:
                assessment = {
                    "finding_id": fid,
                    "summary": f"Impact assessment failed: {exc}",
                    "data_at_risk": "",
                    "systems_at_risk": "",
                    "users_at_risk": "",
                    "severity": er.get("verdict", ""),
                }
            assessments.append(assessment)
            print(f"  [red-team] impact written for {fid}")

            # Backfill the exploit_result's `impact` field with the fuller summary
            for i, r in enumerate(updated_results):
                if r is er:
                    updated_results[i] = {**r, "impact": assessment.get("summary") or r.get("impact", "")}
                    break

    return {**state, "impact_assessments": assessments, "exploit_results": updated_results}


# ---------------------------------------------------------------------------
# Node 5 — chain_findings  (gated separately by --chain-findings)
# ---------------------------------------------------------------------------

_CHAIN_SYSTEM = """\
You are a senior penetration tester writing the attack-chain ("kill chain") \
narrative section of a report for an authorised engagement. You will be shown a \
set of INDEPENDENTLY CONFIRMED AND EXPLOITED vulnerabilities. Identify any \
realistic sequences where chaining two or more of them together produces a worse \
outcome than any single finding alone — for example: information disclosure -> \
credential theft -> privilege escalation -> full compromise, or SSRF -> internal \
service access -> data exfiltration.

Only report chains that are logically and technically supported by the findings \
shown below — do not invent connections the evidence doesn't support. If no \
meaningful chain exists, return an empty "chains" list. Write each narrative as a \
concrete attacker story with concrete steps, not generic platitudes."""

_CHAIN_HUMAN = """\
## Independently exploited findings

{findings_block}

---
Return ONLY a JSON object (no markdown fence, no extra text) with this shape:
{{
  "chains": [
    {{
      "finding_ids": ["<id>", "<id>", "..."],
      "narrative": "<concrete, step-by-step attacker story showing how chaining these findings produces a worse outcome>",
      "combined_severity": "Critical"|"High"|"Medium"|"Low",
      "combined_impact": "<concrete statement of the combined outcome>"
    }}
  ]
}}"""

_chain_prompt = ChatPromptTemplate.from_messages([
    ("system", _CHAIN_SYSTEM),
    ("human", _CHAIN_HUMAN),
])


def chain_findings_node(state: dict) -> dict:
    config = state.get("config", {})
    if not config.get("chain_findings"):
        return {**state, "attack_chains": []}

    exploit_results: list[dict] = state.get("exploit_results", [])
    exploited = [er for er in exploit_results if er.get("verdict") == "Exploitable"]
    if len(exploited) < 2:
        print("[red-team] chain_findings — fewer than 2 exploited findings; nothing to chain.")
        return {**state, "attack_chains": []}

    llm_by_id = {lf["finding"]["id"]: lf for lf in state.get("llm_findings", [])}
    impact_by_id = {ia["finding_id"]: ia for ia in state.get("impact_assessments", [])}

    items = []
    for er in exploited:
        lf = llm_by_id.get(er["finding_id"])
        if not lf:
            continue
        f = lf["finding"]
        impact = impact_by_id.get(er["finding_id"], {})
        items.append({
            "id": f["id"],
            "issue": f["issue"],
            "location": f"{f['file']}:{f['line']}" if f.get("file") else "(dependency)",
            "attack_vector": lf.get("attack_vector", ""),
            "impact": impact.get("summary") or er.get("impact", ""),
        })

    if len(items) < 2:
        return {**state, "attack_chains": []}

    model = config.get("model", DEFAULT_MODEL)
    print(f"\n[red-team] chain_findings — analysing {len(items)} exploited finding(s) for chains...")

    findings_block = "\n\n".join(
        f"### {it['id']}\n"
        f"- Issue: {it['issue']}\n"
        f"- Location: {it['location']}\n"
        f"- Attack vector: {it['attack_vector']}\n"
        f"- Impact: {it['impact']}"
        for it in items
    )

    chains: list[dict] = []
    try:
        llm = get_llm(model=model, temperature=0.2)
        chain = _chain_prompt | llm | _str_parser
        raw = chain.invoke({"findings_block": findings_block})
        data = _parse_json(raw)
        valid_ids = {it["id"] for it in items}
        for c in data.get("chains", []):
            fids = [fid for fid in c.get("finding_ids", []) if fid in valid_ids]
            # de-dupe while preserving order
            seen = set()
            fids = [fid for fid in fids if not (fid in seen or seen.add(fid))]
            if len(fids) < 2:
                continue
            chains.append({
                "finding_ids": fids,
                "narrative": c.get("narrative", ""),
                "combined_severity": c.get("combined_severity", "High"),
                "combined_impact": c.get("combined_impact", ""),
            })
    except Exception as exc:
        print(f"  [red-team] chain analysis failed: {exc}")

    print(f"  [red-team] {len(chains)} attack chain(s) identified")
    return {**state, "attack_chains": chains}


# ---------------------------------------------------------------------------
# Subgraph assembly + the single node/route pair the main graph plugs into
# ---------------------------------------------------------------------------

def _build_red_team_subgraph():
    graph = StateGraph(dict)

    graph.add_node("plan_attack", plan_attack_node)
    graph.add_node("generate_poc", generate_poc_node)
    graph.add_node("execute_poc", execute_poc_node)
    graph.add_node("capture_evidence", capture_evidence_node)
    graph.add_node("chain_findings", chain_findings_node)

    graph.set_entry_point("plan_attack")
    graph.add_edge("plan_attack", "generate_poc")
    graph.add_edge("generate_poc", "execute_poc")
    graph.add_edge("execute_poc", "capture_evidence")
    graph.add_edge("capture_evidence", "chain_findings")
    graph.add_edge("chain_findings", END)

    return graph.compile()


_subgraph = None  # built lazily, once, on first use


def route_red_team(state: dict) -> str:
    """Conditional edge for the *main* graph: continue into the red-team
    subgraph after `exploitation` only when --red-team is enabled — otherwise
    fall through to `report` exactly as the pipeline already did."""
    if state.get("config", {}).get("red_team"):
        return "red_team"
    return "report"


def red_team_node(state: dict) -> dict:
    """Wrapper node registered in the main graph — runs the whole red-team
    subgraph as a single pipeline step, immediately after `exploitation`."""
    config = state.get("config", {})

    # Defence in depth: route_red_team only sends us here when --red-team is
    # set, but this node enforces the same --exploit/--i-own-this-target gate
    # as `exploitation` so it is also safe to invoke directly / in tests.
    if not _is_red_team_ready(config):
        print(
            "[red-team] --red-team requires --exploit and --i-own-this-target "
            "(same as the exploitation node) — skipping."
        )
        return {
            **state,
            "attack_plans": [],
            "poc_scripts": [],
            "impact_assessments": [],
            "attack_chains": [],
        }

    print(
        "\n[red-team] === Red-team subgraph starting "
        "(plan -> generate -> execute -> assess -> chain) ===\n"
        "[!] WARNING: generated PoCs run with the same caveats as the standard "
        "exploitation node — sandboxed and time-boxed, but not a kernel-level\n"
        "    jail when Docker is unavailable. Review audit_exploits output before "
        "trusting it blindly.\n"
    )

    global _subgraph
    if _subgraph is None:
        _subgraph = _build_red_team_subgraph()

    return _subgraph.invoke(state)
