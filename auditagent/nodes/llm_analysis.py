"""LLM analysis node — sends each finding to the LLM and returns enriched results."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from auditagent.llm import get_client, analyse_finding
from auditagent.utils import DEFAULT_MODEL


MAX_WORKERS = 4   # light concurrency; OpenRouter rate-limits gently
MAX_FINDINGS = 50  # cost guard: warn and cap if the project has a huge number of findings


def llm_analysis_node(state: dict) -> dict:
    raw_findings: list[dict] = state.get("raw_findings", [])
    config = state.get("config", {})
    model = config.get("model", DEFAULT_MODEL)

    if not raw_findings:
        return {**state, "llm_findings": []}

    if len(raw_findings) > MAX_FINDINGS:
        print(
            f"[warn] {len(raw_findings)} findings found — capping LLM analysis at {MAX_FINDINGS} "
            f"to control cost. Use --no-semgrep or fix findings incrementally."
        )
        raw_findings = raw_findings[:MAX_FINDINGS]

    client = get_client()
    llm_findings: list[dict] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(analyse_finding, f, model, client): f
            for f in raw_findings
        }
        for future in as_completed(futures):
            orig_finding = futures[future]
            try:
                result = future.result()
                llm_findings.append(result)
            except Exception as exc:
                # Fallback for any thread-level error not caught inside analyse_finding
                llm_findings.append({
                    "finding": orig_finding,
                    "confirmed": False,
                    "severity": orig_finding.get("severity", "Medium"),
                    "attack_vector": "Thread error — review manually.",
                    "explanation": f"Unexpected error: {exc}",
                    "fix": "Review the code manually.",
                    "exploitable": False,
                })

    # Sort by severity: Critical first
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    llm_findings.sort(key=lambda x: order.get(x.get("severity", "Low"), 3))

    return {**state, "llm_findings": llm_findings}
