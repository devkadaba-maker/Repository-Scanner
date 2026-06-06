#!/usr/bin/env python3
"""
server.py — FastAPI web server for the security audit agent.

Serves a streaming web UI that wraps the LangGraph audit pipeline.
Each pipeline node emits Server-Sent Events (SSE) so the browser
receives live progress updates.

Run with:
    ./start_server.sh
or:
    uvicorn server:app --host 0.0.0.0 --port 7860 --reload
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

# ---------------------------------------------------------------------------
# Bootstrap: ensure the project root is importable before anything else
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from audit import build_graph
from auditagent.state import AuditState
from auditagent.utils import DEFAULT_MODEL
from auditagent.github_integration import (
    GitHubIntegration,
    GitHubError,
    GitHubAuthError,
    GitHubRateLimitError,
    GitHubNotPythonError,
    CloneResult,
    RepoInfo,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
FRONTEND_DIR = BASE_DIR / "frontend"
SENTINEL = object()  # signals end-of-stream in async queues

# ---------------------------------------------------------------------------
# In-memory job store
# ---------------------------------------------------------------------------


class JobStatus:
    """Tracks one audit job's lifecycle."""

    def __init__(self, job_id: str, project_path: str) -> None:
        self.job_id = job_id
        self.project_path = project_path
        self.created_at: str = datetime.utcnow().isoformat() + "Z"
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None

        # "pending" | "running" | "complete" | "error"
        self.status: str = "pending"
        self.error: Optional[str] = None

        # Final LangGraph state (set when the pipeline finishes)
        self.final_state: Optional[dict] = None

        # Summary counts written when complete
        self.summary: dict = {}

        # Temporary directory created for GitHub clones (cleaned up later)
        self.tmp_dir: Optional[str] = None

        # asyncio event loop used by the SSE endpoint — set at stream time
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # asyncio.Queue that SSE generators read from
        self._queue: asyncio.Queue = asyncio.Queue()

    # ------------------------------------------------------------------
    # Thread-safe event emission (called from background threads)
    # ------------------------------------------------------------------

    def emit(self, event: dict) -> None:
        """Put an event onto the asyncio queue from any thread."""
        if self._loop is not None and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._queue.put_nowait, event)

    def close(self) -> None:
        """Signal the SSE generator that the stream is finished."""
        if self._loop is not None and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._queue.put_nowait, SENTINEL)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_summary_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "project_path": self.project_path,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary,
            "error": self.error,
        }


# Global job store: { job_id: JobStatus }
_jobs: dict[str, JobStatus] = {}
_jobs_lock = threading.Lock()


def _register_job(job: JobStatus) -> None:
    with _jobs_lock:
        _jobs[job.job_id] = job


def _get_job(job_id: str) -> JobStatus:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id!r} not found")
    return job


def _recent_jobs(n: int = 10) -> list[dict]:
    with _jobs_lock:
        jobs = list(_jobs.values())
    jobs.sort(key=lambda j: j.created_at, reverse=True)
    return [j.to_summary_dict() for j in jobs[:n]]


# ---------------------------------------------------------------------------
# Pipeline runner (executed in a background thread)
# ---------------------------------------------------------------------------

NODE_LABELS: dict[str, str] = {
    "recon": "Recon (tech stack, files, deps)",
    "static_analysis": "Static analysis (bandit + semgrep)",
    "dependency_audit": "Dependency audit (pip-audit)",
    "llm_analysis": "LLM analysis (confirming findings)",
    "exploitation": "Safe exploitation (PoC validation)",
    "report": "Report generation",
}

NODE_MESSAGES: dict[str, str] = {
    "recon": "Recon started — scanning project structure",
    "static_analysis": "Static analysis started — running bandit & semgrep",
    "dependency_audit": "Dependency audit started — running pip-audit",
    "llm_analysis": "LLM analysis started — confirming findings with AI",
    "exploitation": "Exploitation node started — validating PoCs safely",
    "report": "Report generation started — compiling findings",
}


def _build_summary(state: dict) -> dict:
    """Distil final state into severity counts."""
    llm_findings = state.get("llm_findings", [])
    confirmed = [f for f in llm_findings if f.get("confirmed")]
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for lf in confirmed:
        sev = lf.get("severity", "Low").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _run_pipeline(job: JobStatus, initial_state: AuditState) -> None:
    """Entry-point for the background thread that drives LangGraph."""
    job.started_at = datetime.utcnow().isoformat() + "Z"
    job.status = "running"

    try:
        graph = build_graph()

        for step in graph.stream(initial_state):
            node_name = next(iter(step))
            if node_name not in NODE_LABELS:
                # LangGraph may emit internal metadata events; skip them
                continue

            node_state: dict = step[node_name]

            # --- node_start was already emitted before graph.stream() loop,
            #     so here we emit node_done after the step is returned ---
            # Emit node_done with a lightweight data snapshot
            done_data: dict[str, Any] = {
                "framework": node_state.get("tech_stack", {}).get("framework", ""),
                "files": len(node_state.get("source_files", [])),
                "raw_findings": len(node_state.get("raw_findings", [])),
                "llm_findings": len(node_state.get("llm_findings", [])),
                "report_path": node_state.get("report_path", ""),
            }
            job.emit({"type": "node_done", "node": node_name, "data": done_data})

            # Emit individual findings as they come in (after llm_analysis)
            if node_name == "llm_analysis":
                for lf in node_state.get("llm_findings", []):
                    if lf.get("confirmed"):
                        raw = lf.get("finding", {})
                        job.emit(
                            {
                                "type": "finding",
                                "severity": lf.get("severity", "Low"),
                                "issue": raw.get("issue", ""),
                                "source": raw.get("source", ""),
                                "file": raw.get("file", ""),
                                "line": raw.get("line", 0),
                                "exploitable": lf.get("exploitable", False),
                            }
                        )

            # Keep the final state updated so /result is always fresh
            job.final_state = node_state

        # ----------------------------------------------------------------
        # Pipeline finished successfully
        # ----------------------------------------------------------------
        final = job.final_state or {}
        summary = _build_summary(final)
        job.summary = summary
        job.status = "complete"
        job.finished_at = datetime.utcnow().isoformat() + "Z"

        job.emit({"type": "complete", "summary": summary})

    except Exception as exc:  # noqa: BLE001
        job.status = "error"
        job.error = str(exc)
        job.finished_at = datetime.utcnow().isoformat() + "Z"
        job.emit({"type": "error", "message": str(exc)})

    finally:
        # Give the SSE generator a moment to drain, then close
        time.sleep(0.2)
        job.close()


# ---------------------------------------------------------------------------
# Helper: emit node_start events *before* the node runs
# We monkey-patch the graph to wrap each node — but a simpler approach is
# to emit node_start from a graph middleware.  LangGraph ≥ 0.1 supports
# streaming; the node_start events are emitted by wrapping the thread runner.
# ---------------------------------------------------------------------------

def _run_pipeline_with_start_events(job: JobStatus, initial_state: AuditState) -> None:
    """
    Thin wrapper that emits node_start before each node by intercepting
    the graph.stream() iterator.  LangGraph yields {node_name: output_state}
    *after* the node completes, so we track which nodes we have seen to
    emit node_start for the *next* step.
    """
    job.started_at = datetime.utcnow().isoformat() + "Z"
    job.status = "running"

    # Emit node_start for "recon" immediately (it's the entry point)
    job.emit(
        {
            "type": "node_start",
            "node": "recon",
            "message": NODE_MESSAGES.get("recon", "Recon started"),
        }
    )

    try:
        graph = build_graph()
        final_state: dict = dict(initial_state)

        for step in graph.stream(initial_state):
            node_name = next(iter(step))
            if node_name not in NODE_LABELS:
                continue

            node_state: dict = step[node_name]
            final_state = node_state

            # ---- node_done for the node that just finished ----
            done_data: dict[str, Any] = {
                "framework": node_state.get("tech_stack", {}).get("framework", ""),
                "files": len(node_state.get("source_files", [])),
                "raw_findings": len(node_state.get("raw_findings", [])),
                "llm_findings": len(node_state.get("llm_findings", [])),
                "report_path": node_state.get("report_path", ""),
            }
            job.emit({"type": "node_done", "node": node_name, "data": done_data})

            # ---- individual findings after llm_analysis ----
            if node_name == "llm_analysis":
                for lf in node_state.get("llm_findings", []):
                    if lf.get("confirmed"):
                        raw = lf.get("finding", {})
                        job.emit(
                            {
                                "type": "finding",
                                "severity": lf.get("severity", "Low"),
                                "issue": raw.get("issue", ""),
                                "source": raw.get("source", ""),
                                "file": raw.get("file", ""),
                                "line": raw.get("line", 0),
                                "exploitable": lf.get("exploitable", False),
                            }
                        )

            # ---- predict node_start for the next node ----
            # We determine the next node by examining which node was just
            # completed and what the routing logic would produce.  Rather
            # than duplicating routing logic we emit a speculative node_start
            # for the common linear path; conditional branches self-correct.
            NEXT_NODE: dict[str, str] = {
                "recon": "static_analysis",
                "static_analysis": "dependency_audit",
                # conditional: dependency_audit → llm_analysis OR report
                "dependency_audit": (
                    "llm_analysis" if node_state.get("raw_findings") else "report"
                ),
                # conditional: llm_analysis → exploitation OR report
                "llm_analysis": (
                    "exploitation"
                    if (
                        node_state.get("config", {}).get("run_exploit")
                        and any(
                            f.get("exploitable") and f.get("confirmed")
                            for f in node_state.get("llm_findings", [])
                        )
                    )
                    else "report"
                ),
                "exploitation": "report",
            }
            next_node = NEXT_NODE.get(node_name)
            if next_node:
                job.emit(
                    {
                        "type": "node_start",
                        "node": next_node,
                        "message": NODE_MESSAGES.get(next_node, f"{next_node} started"),
                    }
                )

            job.final_state = node_state

        # ----------------------------------------------------------------
        # Done
        # ----------------------------------------------------------------
        summary = _build_summary(final_state)
        job.summary = summary
        job.status = "complete"
        job.finished_at = datetime.utcnow().isoformat() + "Z"
        job.emit({"type": "complete", "summary": summary})

    except Exception as exc:  # noqa: BLE001
        job.status = "error"
        job.error = str(exc)
        job.finished_at = datetime.utcnow().isoformat() + "Z"
        job.emit({"type": "error", "message": str(exc)})

    finally:
        time.sleep(0.2)
        job.close()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Security Audit Agent",
    description="Streaming web interface for the LangGraph security audit pipeline.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files if the frontend directory has content
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class StartAuditRequest(BaseModel):
    project_path: str = Field(..., description="Absolute path to the project to audit")
    run_semgrep: bool = Field(True, description="Run semgrep in addition to bandit")
    run_exploit: bool = Field(False, description="Run safe exploitation / PoC validation")
    i_own_target: bool = Field(False, description="Confirm you own / are authorised to test this target")
    model: str = Field(DEFAULT_MODEL, description="OpenRouter model ID")
    output: str = Field("audit_report.md", description="Report filename (no path separators)")


class CloneRequest(BaseModel):
    url: str = Field(..., description="GitHub repository URL to clone")
    job_id: Optional[str] = Field(None, description="Optional job_id to attach clone path to")


class CloneResponse(BaseModel):
    path: str
    job_id: Optional[str] = None


# ---------------------------------------------------------------------------
# GitHub-specific request / response models
# ---------------------------------------------------------------------------


class GitHubInfoRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository URL (any supported form)")


class GitHubValidateResponse(BaseModel):
    valid: bool
    normalized_url: str
    is_private: Optional[bool] = None


class GitHubCloneRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository URL to clone")
    branch: Optional[str] = Field(None, description="Branch to clone (default: repo default)")
    github_token: Optional[str] = Field(
        None,
        description="GitHub Personal Access Token (overrides GITHUB_TOKEN env var)",
    )


class GitHubCloneResponse(BaseModel):
    path: str
    repo_info: dict
    job_id: str


class GitHubAuditRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository URL to clone and audit")
    branch: Optional[str] = Field(None, description="Branch to clone (default: repo default)")
    github_token: Optional[str] = Field(
        None,
        description="GitHub Personal Access Token (overrides GITHUB_TOKEN env var)",
    )
    no_semgrep: bool = Field(False, description="Skip semgrep static analysis")
    model: str = Field(DEFAULT_MODEL, description="OpenRouter model ID")


class GitHubAuditResponse(BaseModel):
    job_id: str
    repo_info: dict
    stream_url: str
    result_url: str


class StartAuditResponse(BaseModel):
    job_id: str
    status: str
    stream_url: str
    result_url: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
async def serve_index() -> FileResponse:
    """Serve the frontend SPA."""
    index = FRONTEND_DIR / "index.html"
    if not index.exists():
        return JSONResponse(
            status_code=200,
            content={
                "message": "Security Audit Agent API is running.",
                "docs": "/docs",
                "openapi": "/openapi.json",
            },
        )
    return FileResponse(str(index))


# NOTE: POST /api/github/clone is defined below (after the helper functions)
# alongside the other GitHub routes.


# ---------------------------------------------------------------------------
# Helper: map GitHubError subclasses to HTTP status codes
# ---------------------------------------------------------------------------


def _github_http_error(exc: GitHubError) -> HTTPException:
    """Convert a GitHubError into the most appropriate HTTPException."""
    if isinstance(exc, GitHubAuthError):
        return HTTPException(status_code=401, detail=str(exc))
    if isinstance(exc, GitHubRateLimitError):
        return HTTPException(status_code=429, detail=str(exc))
    if isinstance(exc, GitHubNotPythonError):
        return HTTPException(status_code=422, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /api/github/validate
# ---------------------------------------------------------------------------


@app.get("/api/github/validate", response_model=GitHubValidateResponse)
async def github_validate(url: str) -> GitHubValidateResponse:
    """
    Validate and normalise a GitHub repository URL.

    Query parameter: ``url`` — any supported GitHub URL form.

    Returns whether the URL is valid and its canonical form.  When a
    GITHUB_TOKEN is configured the endpoint also reports whether the
    repository is private.
    """
    gh = GitHubIntegration()
    is_valid, normalized = gh.validate_url(url)

    if not is_valid:
        return GitHubValidateResponse(valid=False, normalized_url=url, is_private=None)

    # Best-effort privacy check (requires API access)
    is_private: Optional[bool] = None
    try:
        info = gh.get_repo_info(normalized)
        is_private = info["is_private"]
    except GitHubError:
        pass

    return GitHubValidateResponse(
        valid=True,
        normalized_url=normalized,
        is_private=is_private,
    )


# ---------------------------------------------------------------------------
# POST /api/github/info
# ---------------------------------------------------------------------------


@app.post("/api/github/info")
async def github_info(req: GitHubInfoRequest) -> JSONResponse:
    """
    Fetch repository metadata via the GitHub API without cloning.

    Returns a :class:`RepoInfo` dict with name, description, stars, language,
    topics, default branch, and privacy status.
    """
    gh = GitHubIntegration()
    try:
        info = gh.get_repo_info(req.repo_url)
    except GitHubError as exc:
        raise _github_http_error(exc) from exc

    return JSONResponse(content=dict(info))


# ---------------------------------------------------------------------------
# POST /api/github/clone  (full replacement of the stub above)
# ---------------------------------------------------------------------------


@app.post("/api/github/clone", response_model=GitHubCloneResponse)
async def github_clone_full(req: GitHubCloneRequest) -> GitHubCloneResponse:
    """
    Clone a GitHub repository into a temporary directory, start an audit job,
    and return the clone path, repo metadata, and the new job_id.

    The audit is *not* started automatically by this endpoint — use
    ``POST /api/github/audit`` for a one-shot clone-and-audit operation.

    Authentication precedence:
    1. ``github_token`` in the request body.
    2. ``GITHUB_TOKEN`` environment variable.
    """
    gh = GitHubIntegration(token=req.github_token)

    try:
        clone_result: CloneResult = gh.clone_repo(
            repo_url=req.repo_url,
            branch=req.branch,
        )
    except GitHubError as exc:
        raise _github_http_error(exc) from exc

    # Register a new job so the caller can wire up SSE streaming
    job_id = str(uuid.uuid4())
    job = JobStatus(job_id=job_id, project_path=clone_result["path"])
    job.tmp_dir = clone_result["path"]
    _register_job(job)

    # Promote CloneResult → RepoInfo shape (drop the path key)
    repo_info_dict = {k: v for k, v in clone_result.items() if k != "path"}

    return GitHubCloneResponse(
        path=clone_result["path"],
        repo_info=repo_info_dict,
        job_id=job_id,
    )


# ---------------------------------------------------------------------------
# POST /api/github/audit  — one-shot clone + audit
# ---------------------------------------------------------------------------


@app.post("/api/github/audit", response_model=GitHubAuditResponse)
async def github_audit(req: GitHubAuditRequest) -> GitHubAuditResponse:
    """
    One-shot endpoint: clone a GitHub repo and immediately start the audit
    pipeline.

    Returns a ``job_id`` for SSE streaming via
    ``GET /api/audit/{job_id}/stream``.

    Requires OPENROUTER_API_KEY to be set on the server.

    Authentication precedence for GitHub:
    1. ``github_token`` in the request body.
    2. ``GITHUB_TOKEN`` environment variable.
    """
    if not os.environ.get("OPENROUTER_API_KEY"):
        raise HTTPException(
            status_code=503,
            detail="OPENROUTER_API_KEY is not set on the server.",
        )

    # ------------------------------------------------------------------
    # Step 1: Clone
    # ------------------------------------------------------------------
    gh = GitHubIntegration(token=req.github_token)

    try:
        clone_result: CloneResult = gh.clone_repo(
            repo_url=req.repo_url,
            branch=req.branch,
        )
    except GitHubError as exc:
        raise _github_http_error(exc) from exc

    project_path = clone_result["path"]

    # ------------------------------------------------------------------
    # Step 2: Register job
    # ------------------------------------------------------------------
    job_id = str(uuid.uuid4())
    job = JobStatus(job_id=job_id, project_path=project_path)
    job.tmp_dir = project_path
    _register_job(job)

    # ------------------------------------------------------------------
    # Step 3: Build initial audit state (GitHub-aware)
    # ------------------------------------------------------------------
    config: dict = {
        "run_semgrep": not req.no_semgrep,
        "run_exploit": False,          # exploitation is disabled for GitHub audits
        "i_own_target": False,
        "model": req.model,
        "output": "audit_report.md",
        # GitHub-specific extras consumed by github_recon_node
        "github_token": req.github_token or os.environ.get("GITHUB_TOKEN") or None,
        "github_url": req.repo_url,
        "github_metadata": {k: v for k, v in clone_result.items() if k != "path"},
    }

    initial_state: AuditState = {
        "project_path": project_path,
        "tech_stack": {},
        "source_files": [],
        "dependencies": [],
        "raw_findings": [],
        "llm_findings": [],
        "exploit_results": [],
        "report_path": "",
        "config": config,
    }

    # ------------------------------------------------------------------
    # Step 4: Launch pipeline in background thread
    # ------------------------------------------------------------------
    thread = threading.Thread(
        target=_run_pipeline_with_start_events,
        args=(job, initial_state),
        daemon=True,
        name=f"gh-audit-{job_id[:8]}",
    )
    thread.start()

    repo_info_dict = {k: v for k, v in clone_result.items() if k != "path"}

    return GitHubAuditResponse(
        job_id=job_id,
        repo_info=repo_info_dict,
        stream_url=f"/api/audit/{job_id}/stream",
        result_url=f"/api/audit/{job_id}/result",
    )


# ---------------------------------------------------------------------------
# POST /api/audit
# ---------------------------------------------------------------------------


@app.post("/api/audit", response_model=StartAuditResponse)
async def start_audit(req: StartAuditRequest) -> StartAuditResponse:
    """
    Start a new audit pipeline run in a background thread.
    Returns a job_id that can be used to stream events or retrieve the result.
    """
    project_path = Path(req.project_path).expanduser().resolve()
    if not project_path.exists():
        raise HTTPException(
            status_code=422,
            detail=f"Project path does not exist: {project_path}",
        )

    if req.run_exploit and not req.i_own_target:
        raise HTTPException(
            status_code=422,
            detail="run_exploit requires i_own_target=true",
        )

    if not os.environ.get("OPENROUTER_API_KEY"):
        raise HTTPException(
            status_code=503,
            detail="OPENROUTER_API_KEY is not set on the server.",
        )

    # Validate output filename
    output = req.output
    if os.sep in output or "/" in output or "\\" in output:
        raise HTTPException(
            status_code=422,
            detail="output must be a plain filename with no path separators.",
        )

    job_id = str(uuid.uuid4())
    job = JobStatus(job_id=job_id, project_path=str(project_path))
    _register_job(job)

    config: dict = {
        "run_semgrep": req.run_semgrep,
        "run_exploit": req.run_exploit,
        "i_own_target": req.i_own_target,
        "model": req.model,
        "output": output,
    }

    initial_state: AuditState = {
        "project_path": str(project_path),
        "tech_stack": {},
        "source_files": [],
        "dependencies": [],
        "raw_findings": [],
        "llm_findings": [],
        "exploit_results": [],
        "report_path": "",
        "config": config,
    }

    thread = threading.Thread(
        target=_run_pipeline_with_start_events,
        args=(job, initial_state),
        daemon=True,
        name=f"audit-{job_id[:8]}",
    )
    thread.start()

    return StartAuditResponse(
        job_id=job_id,
        status="running",
        stream_url=f"/api/audit/{job_id}/stream",
        result_url=f"/api/audit/{job_id}/result",
    )


# ---------------------------------------------------------------------------
# GET /api/audit/{job_id}/stream  — SSE
# ---------------------------------------------------------------------------


async def _sse_generator(job: JobStatus) -> AsyncGenerator[str, None]:
    """
    Async generator that yields SSE-formatted lines.

    The background thread puts dicts (or SENTINEL) into job._queue via
    loop.call_soon_threadsafe().  We just await each item here.
    """
    # Wire the current event loop into the job so the background thread
    # can call call_soon_threadsafe on it.
    loop = asyncio.get_event_loop()
    job._loop = loop
    job._queue = asyncio.Queue()  # fresh queue for this connection

    # If the job already finished before the client connected, replay events
    # would require a persistent log — instead we emit a synthetic summary.
    if job.status in ("complete", "error") and job.final_state is not None:
        if job.status == "complete":
            yield f"data: {json.dumps({'type': 'complete', 'summary': job.summary})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'error', 'message': job.error or 'Unknown error'})}\n\n"
        return

    # Keep-alive comment every 15 s to prevent proxy timeouts
    TIMEOUT = 15.0

    while True:
        try:
            item = await asyncio.wait_for(job._queue.get(), timeout=TIMEOUT)
        except asyncio.TimeoutError:
            # Send a keep-alive ping
            yield ": keep-alive\n\n"
            continue

        if item is SENTINEL:
            break

        yield f"data: {json.dumps(item)}\n\n"


@app.get("/api/audit/{job_id}/stream")
async def stream_audit(job_id: str) -> StreamingResponse:
    """
    SSE endpoint.  The client should connect here immediately after
    POST /api/audit and will receive events as each LangGraph node completes.
    """
    job = _get_job(job_id)
    return StreamingResponse(
        _sse_generator(job),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        },
    )


# ---------------------------------------------------------------------------
# GET /api/audit/{job_id}/result
# ---------------------------------------------------------------------------


@app.get("/api/audit/{job_id}/result")
async def get_result(job_id: str) -> JSONResponse:
    """Return the full final LangGraph state for a completed job."""
    job = _get_job(job_id)
    if job.status == "running":
        return JSONResponse(
            status_code=202,
            content={"detail": "Audit is still running.", "status": "running"},
        )
    if job.status == "error":
        return JSONResponse(
            status_code=500,
            content={"detail": job.error, "status": "error"},
        )
    if job.final_state is None:
        return JSONResponse(
            status_code=404,
            content={"detail": "No result available yet.", "status": job.status},
        )

    # The final state may contain non-serialisable objects; convert carefully
    def _safe(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _safe(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_safe(i) for i in obj]
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        return str(obj)

    return JSONResponse(content=_safe(job.final_state))


# ---------------------------------------------------------------------------
# GET /api/jobs
# ---------------------------------------------------------------------------


@app.get("/api/jobs")
async def list_jobs() -> JSONResponse:
    """Return the 10 most recent jobs with summary information."""
    return JSONResponse(content=_recent_jobs(10))


# ---------------------------------------------------------------------------
# GET /api/audit/{job_id}  — single job status
# ---------------------------------------------------------------------------


@app.get("/api/audit/{job_id}")
async def get_job(job_id: str) -> JSONResponse:
    """Return status and summary for a single job."""
    job = _get_job(job_id)
    return JSONResponse(content=job.to_summary_dict())


# ---------------------------------------------------------------------------
# Startup / shutdown lifecycle
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def on_startup() -> None:
    print()
    print("=" * 60)
    print("  Security Audit Agent — Web Server")
    print("=" * 60)
    print(f"  URL        : http://localhost:7860")
    print(f"  API docs   : http://localhost:7860/docs")
    print(f"  Model      : {DEFAULT_MODEL}")
    print(f"  API key    : {'set' if os.environ.get('OPENROUTER_API_KEY') else 'NOT SET — audits will fail'}")
    print("=" * 60)
    print()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    print("\nServer shutting down.")


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=7860,
        reload=True,
        log_level="info",
    )
