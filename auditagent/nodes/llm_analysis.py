"""LLM analysis node — sends each finding to the LLM and returns enriched results."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from auditagent.llm import get_client, analyse_finding


MAX_WORKERS = 4   # light concurrency; OpenRouter rate-limits gently


def llm_analysis_node(state: dict) -> dict:
    raw_findings: list[dict] = state.get("raw_findings", [])
    config = state.get("config", {})
    model = config.get("model", "xiaomi/mimo-v2.5-pro")

    if not raw_findings:
        return {**state, "llm_findings": []}

    client = get_client()
    llm_findings: list[dict] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(analyse_finding, f, model, client): f
            for f in raw_findings
        }
        for future in as_completed(futures):
            result = future.result()
            llm_findings.append(result)

    # Sort by severity: Critical first
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    llm_findings.sort(key=lambda x: order.get(x.get("severity", "Low"), 3))

    return {**state, "llm_findings": llm_findings}
