"""LLM analysis node — runs the LangChain analysis chain over all findings."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from auditagent.llm import analyse_finding
from auditagent.utils import DEFAULT_MODEL


MAX_WORKERS = 10  # DeepSeek handles high concurrency well
MAX_FINDINGS = 200  # cost guard — raised so thorough scans aren't truncated


def llm_analysis_node(state: dict) -> dict:
    raw_findings: list[dict] = state.get("raw_findings", [])
    config = state.get("config", {})
    model = config.get("model", DEFAULT_MODEL)

    if not raw_findings:
        return {**state, "llm_findings": []}

    if len(raw_findings) > MAX_FINDINGS:
        print(
            f"[warn] {len(raw_findings)} findings — capping LLM analysis at {MAX_FINDINGS} "
            "to control cost. Fix findings incrementally to bring this below the cap."
        )
        raw_findings = raw_findings[:MAX_FINDINGS]

    llm_findings: list[dict] = []

    # Each thread gets its own ChatOpenAI instance (not thread-safe to share)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(analyse_finding, f, model): f
            for f in raw_findings
        }
        for future in as_completed(futures):
            orig_finding = futures[future]
            try:
                llm_findings.append(future.result())
            except Exception as exc:
                llm_findings.append({
                    "finding": orig_finding,
                    "confirmed": False,
                    "severity": orig_finding.get("severity", "Medium"),
                    "attack_vector": "Thread error — review manually.",
                    "explanation": f"Unexpected error: {exc}",
                    "fix": "Review the code manually.",
                    "exploitable": False,
                })

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    llm_findings.sort(key=lambda x: order.get(x.get("severity", "Low"), 3))

    return {**state, "llm_findings": llm_findings}
