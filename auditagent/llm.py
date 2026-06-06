"""LangChain LLM client and chains for the audit agent.

Uses langchain-openai's ChatOpenAI pointed at OpenRouter's OpenAI-compatible
endpoint. Chains are built with ChatPromptTemplate + output parsers (LCEL).
"""

from __future__ import annotations

import json
import os
import time

from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from auditagent.utils import DEFAULT_MODEL


def get_llm(model: str = DEFAULT_MODEL, temperature: float = 0.1) -> ChatOpenAI:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "OPENROUTER_API_KEY is not set. "
            "Copy .env.example to .env and add your key."
        )
    return ChatOpenAI(
        model=model,
        openai_api_key=api_key,
        openai_api_base="https://openrouter.ai/api/v1",
        temperature=temperature,
        max_tokens=1024,
        model_kwargs={
            "extra_headers": {
                "HTTP-Referer": "https://github.com/security-audit-agent",
                "X-Title": "security-audit-agent",
            }
        },
    )


# ---------------------------------------------------------------------------
# Kept for backwards compat with exploitation.py which imports get_client
# ---------------------------------------------------------------------------
def get_client():
    return get_llm()


# ---------------------------------------------------------------------------
# Analysis chain
# ---------------------------------------------------------------------------

_ANALYSIS_SYSTEM = """\
You are an expert application security engineer performing an authorised,
ethical security audit of a Python web application owned by the requester.

Your task: analyse the provided security finding and return a structured JSON
assessment. Be precise, technical, and actionable."""

_ANALYSIS_HUMAN = """\
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
  "explanation": "<detailed technical explanation (2-4 sentences)>",
  "fix": "<concrete remediation steps (2-4 sentences)>",
  "exploitable": true|false
}}"""

_analysis_prompt = ChatPromptTemplate.from_messages([
    ("system", _ANALYSIS_SYSTEM),
    ("human", _ANALYSIS_HUMAN),
])


def analyse_finding(
    finding: dict,
    model: str = DEFAULT_MODEL,
    client=None,  # ignored; kept for call-site compatibility
    retries: int = 3,
) -> dict:
    """Run the analysis chain for a single Finding. Returns an LLMFinding dict."""
    llm = get_llm(model=model, temperature=0.1)
    chain = _analysis_prompt | llm | JsonOutputParser()

    inputs = {
        "source": finding["source"],
        "issue": finding["issue"],
        "file": finding["file"],
        "line": finding["line"],
        "severity": finding["severity"],
        "code_snippet": finding["code_snippet"] or "(no snippet available)",
        "metadata": json.dumps(finding.get("metadata", {}), indent=2),
    }

    for attempt in range(retries):
        try:
            data = chain.invoke(inputs)
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
                return {
                    "finding": finding,
                    "confirmed": False,
                    "severity": finding.get("severity", "Medium"),
                    "attack_vector": "Analysis failed — review manually.",
                    "explanation": f"LLM analysis error: {exc}",
                    "fix": "Review the code manually.",
                    "exploitable": False,
                }


# ---------------------------------------------------------------------------
# PoC generation chain
# ---------------------------------------------------------------------------

_POC_SYSTEM = """\
You are an expert penetration tester performing an authorised, ethical security
audit of a Python web application the requester owns and has authorised for
testing. Your task is to produce a NON-DESTRUCTIVE proof-of-concept that
confirms exploitability of the given vulnerability against a locally running
instance.

Rules:
- Target: 127.0.0.1 only (substituted via {{host}}:{{port}} placeholders).
- No data deletion, modification, or exfiltration beyond a single benign read.
- No DoS payloads, no binary exploit shellcode.
- Output a self-contained Python snippet using `httpx` (already installed)."""

_POC_HUMAN = """\
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

The target app is running at http://{{host}}:{{port}}.
Produce ONLY a Python snippet (no markdown fences) that:
1. Imports httpx (and stdlib only — no extras).
2. Sends one or more non-destructive HTTP requests that demonstrate the vulnerability.
3. Prints the result and a clear VERDICT line: "VERDICT: Exploitable" or
   "VERDICT: Not exploitable" or "VERDICT: Inconclusive".
4. Also prints a one-line IMPACT statement."""

_poc_prompt = ChatPromptTemplate.from_messages([
    ("system", _POC_SYSTEM),
    ("human", _POC_HUMAN),
])


def generate_poc(
    llm_finding: dict,
    model: str = DEFAULT_MODEL,
    client=None,  # ignored; kept for call-site compatibility
    retries: int = 2,
) -> str:
    """Generate a non-destructive PoC script for a confirmed finding."""
    llm = get_llm(model=model, temperature=0.2)
    chain = _poc_prompt | llm | StrOutputParser()

    f = llm_finding["finding"]
    inputs = {
        "issue": f["issue"],
        "file": f["file"],
        "line": f["line"],
        "attack_vector": llm_finding["attack_vector"],
        "severity": llm_finding["severity"],
        "code_snippet": f["code_snippet"] or "(no snippet available)",
    }

    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            return chain.invoke(inputs)
        except Exception as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(2 ** attempt)

    raise RuntimeError(f"PoC generation failed after {retries} attempts: {last_exc}") from last_exc
