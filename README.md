# security-audit-agent

A LangGraph-based ethical security audit agent for web & application projects, in any language (Python, JavaScript/TypeScript, Go, Java, Ruby, PHP, and more).

## What it does

Runs a multi-node pipeline against a local project you own:

```
recon → static_analysis → dependency_audit → [route]
    ├─ no findings → report
    └─ findings   → llm_analysis → [route_exploit]
                        ├─ --exploit & exploitable → exploitation → report
                        └─ else → report
```

1. **Recon** — detects tech stack, walks source files, parses deps
2. **Static analysis** — bandit (always) + semgrep (optional)
3. **Dependency audit** — pip-audit CVE scan
4. **LLM analysis** — confirms findings, rates severity, explains attack vectors, proposes fixes
5. **Exploitation** — safe local PoC validation (flag-gated, localhost-only)
6. **Report** — Markdown report grouped by severity

LLM: [DeepSeek V4 Flash](https://openrouter.ai/deepseek/deepseek-v4-flash) via OpenRouter.

## Setup

```bash
# 1. Create venv (Python 3.11)
/Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set your OpenRouter API key
cp .env.example .env
# Edit .env: OPENROUTER_API_KEY=sk-or-v1-...
```

## Usage

```bash
# Basic audit (no semgrep, no exploit)
python audit.py path/to/your/project --no-semgrep

# Full audit with semgrep
python audit.py path/to/your/project

# With safe exploitation / PoC validation
python audit.py path/to/your/project --exploit --i-own-this-target

# Custom model or output file
python audit.py path/to/your/project --model deepseek/deepseek-v4-flash --output report.md
```

The agent prints a Rich summary table to stdout and writes `audit_report.md` to the project root.
Exit code 1 = Critical or High findings found; 0 = clean.

## Test

Run against the bundled vulnerable fixture:

```bash
python audit.py tests/fixtures/vulnerable_app --no-semgrep
```

Expected: 8 bandit findings + 9 CVEs → 17 confirmed findings, report at
`tests/fixtures/vulnerable_app/audit_report.md`.

## Ethical use

This tool is for testing **your own projects** or systems you are explicitly authorised to test.
The `--exploit` flag requires `--i-own-this-target` as an explicit acknowledgment.
PoC scripts are non-destructive, target 127.0.0.1 only, and are saved to `exploits/` for review.
