"""OpenRouter client and prompt helpers for the audit agent.

Uses the official openai Python SDK pointed at OpenRouter's OpenAI-compatible
endpoint.  No LangChain wrapper; no Anthropic SDK.
"""

from __future__ import annotations

import json
import os
import re
import time

from openai import OpenAI

from auditagent.utils import DEFAULT_MODEL


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------

def get_client() -> OpenAI:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "OPENROUTER_API_KEY is not set. "
            "Copy .env.example to .env and add your key."
        )
    return OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        default_headers={
            "HTTP-Referer": "https://github.com/security-audit-agent",
            "X-Title": "security-audit-agent",
        },
    )


def _strip_fence(raw: str) -> str:
    """Strip markdown code fences from LLM output robustly."""
    raw = raw.strip()
    # Match ```[lang]\n...\n```
    match = re.search(r"```[a-zA-Z]*\s*\n?([\s\S]+?)\n?\s*```", raw)
    if match:
        return match.group(1).strip()
    return raw


# ---------------------------------------------------------------------------
# Analysis prompt
# ---------------------------------------------------------------------------

ANALYSIS_SYSTEM = """\
You are an expert application security engineer performing an authorised,
ethical security audit of a Python web application owned by the requester.

Your task: analyse the provided security finding and return a structured JSON
assessment.  Be precise, technical, and actionable.
"""

ANALYSIS_USER_TMPL = """\
## Finding details
- Source tool : {source}
- Issue       : {issue}
- File        : {file}
- Line        : {line}
- Raw severity: {severity}

## Code snippet
```python
{code_snippet}
```

## Additional metadata
{metadata}

---
Return ONLY a JSON object (no markdown fence, no extra text) with these keys:
{{
  "confirmed": true|false,
  "severity": "Critical"|"High"|"Medium"|"Low",
  "attack_vector": "<one sentence describing how an attacker exploits this>",
  "explanation": "<detailed technical explanation (2–4 sentences)>",
  "fix": "<concrete remediation steps (2–4 sentences)>",
  "exploitable": true|false
}}
"""


def analyse_finding(
    finding: dict,
    model: str = DEFAULT_MODEL,
    client: OpenAI | None = None,
    retries: int = 3,
) -> dict:
    """Call the LLM to analyse a single Finding and return an LLMFinding dict."""
    if client is None:
        client = get_client()

    prompt = ANALYSIS_USER_TMPL.format(
        source=finding["source"],
        issue=finding["issue"],
        file=finding["file"],
        line=finding["line"],
        severity=finding["severity"],
        code_snippet=finding["code_snippet"] or "(no snippet available)",
        metadata=json.dumps(finding.get("metadata", {}), indent=2),
    )

    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": ANALYSIS_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=800,
            )
            raw = resp.choices[0].message.content.strip()
            raw = _strip_fence(raw)
            data = json.loads(raw)
            return {
                "finding": finding,
                "confirmed": bool(data.get("confirmed", True)),
                "severity": data.get("severity", "Medium"),
                "attack_vector": data.get("attack_vector", ""),
                "explanation": data.get("explanation", ""),
                "fix": data.get("fix", ""),
                "exploitable": bool(data.get("exploitable", False)),
            }
        except Exception as exc:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                # Fallback: mark as unconfirmed so it doesn't inflate severity counts
                return {
                    "finding": finding,
                    "confirmed": False,
                    "severity": finding.get("severity", "Medium"),
                    "attack_vector": "Analysis failed – review manually.",
                    "explanation": f"LLM analysis error: {exc}",
                    "fix": "Review the code manually.",
                    "exploitable": False,
                }


# ---------------------------------------------------------------------------
# Exploitation PoC prompt
# ---------------------------------------------------------------------------

POC_SYSTEM = """\
You are an expert penetration tester performing an authorised, ethical security
audit of a Python web application the requester owns and has authorised for
testing.  Your task is to produce a NON-DESTRUCTIVE proof-of-concept that
confirms exploitability of the given vulnerability against a locally running
instance.

Rules:
- Target: 127.0.0.1 only (substituted via {host}:{port} placeholders).
- No data deletion, modification, or exfiltration beyond a single benign read.
- No DoS payloads, no binary exploit shellcode.
- Output a self-contained Python snippet using `httpx` (already installed).
"""

POC_USER_TMPL = """\
## Confirmed vulnerability
- Issue       : {issue}
- File        : {file}
- Line        : {line}
- Attack vector: {attack_vector}
- Severity    : {severity}

## Code snippet
```python
{code_snippet}
```

The target app is running at http://{{host}}:{{port}} .
Produce ONLY a Python snippet (no markdown fences) that:
1. Imports httpx (and stdlib only — no extras).
2. Sends one or more non-destructive HTTP requests that demonstrate the vulnerability.
3. Prints the result and a clear VERDICT line: "VERDICT: Exploitable" or
   "VERDICT: Not exploitable" or "VERDICT: Inconclusive".
4. Also prints a one-line IMPACT statement.
"""


def generate_poc(
    llm_finding: dict,
    model: str = DEFAULT_MODEL,
    client: OpenAI | None = None,
    retries: int = 2,
) -> str:
    """Ask the LLM to generate a non-destructive PoC script for a confirmed finding."""
    if client is None:
        client = get_client()

    f = llm_finding["finding"]
    prompt = POC_USER_TMPL.format(
        issue=f["issue"],
        file=f["file"],
        line=f["line"],
        attack_vector=llm_finding["attack_vector"],
        severity=llm_finding["severity"],
        code_snippet=f["code_snippet"] or "(no snippet available)",
    )

    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": POC_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=1200,
            )
            poc = resp.choices[0].message.content.strip()
            return _strip_fence(poc)
        except Exception as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(2 ** attempt)

    raise RuntimeError(f"PoC generation failed after {retries} attempts: {last_exc}") from last_exc
