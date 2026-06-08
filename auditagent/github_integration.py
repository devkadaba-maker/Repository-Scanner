"""
auditagent/github_integration.py

Complete GitHub integration layer for the security audit agent.

Provides:
- GitHubIntegration class: clone repos, fetch metadata, list Python files,
  validate URLs, and clean up temp directories.
- CloneResult / RepoInfo TypedDicts that match the API contract.

Authentication:
- Token is read from the GITHUB_TOKEN environment variable or passed directly.
- Without a token the GitHub REST API allows 60 req/hr (public repos only).
- With a token the limit rises to 5 000 req/hr.

Dependencies (add via requirements-github.txt):
    PyGithub>=2.1.0
    gitpython>=3.1.40
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional
from typing import TypedDict

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Optional import guard for PyGithub
# ---------------------------------------------------------------------------
try:
    from github import Github, GithubException, Auth as GithubAuth
    _PYGITHUB_AVAILABLE = True
except ImportError:
    _PYGITHUB_AVAILABLE = False
    Github = None  # type: ignore[assignment,misc]
    GithubException = Exception  # type: ignore[assignment,misc]
    GithubAuth = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# TypedDicts
# ---------------------------------------------------------------------------

class RepoInfo(TypedDict):
    """GitHub repository metadata (no local path)."""
    name: str
    full_name: str
    description: str
    default_branch: str
    language: str
    stars: int
    size_kb: int
    clone_url: str
    topics: list[str]
    is_private: bool


class CloneResult(TypedDict):
    """Result of a successful clone operation, including the local path."""
    path: str
    repo_name: str
    full_name: str
    description: str
    default_branch: str
    language: str
    stars: int
    size_kb: int
    clone_url: str
    topics: list[str]
    is_private: bool


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class GitHubError(Exception):
    """User-friendly error raised by GitHubIntegration."""


class GitHubAuthError(GitHubError):
    """Raised when a token is required but missing / invalid."""


class GitHubRateLimitError(GitHubError):
    """Raised when the GitHub API rate limit is exceeded."""


class GitHubNotPythonError(GitHubError):
    """Raised when the repository is not detected as a Python project."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GITHUB_SSH_RE = re.compile(
    r"^git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$"
)
_GITHUB_HTTPS_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/?#]+?)(?:\.git)?(?:[/?#].*)?$"
)
_SHORTHAND_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)$"
)


def _parse_github_url(url: str) -> tuple[str, str] | None:
    """
    Extract (owner, repo) from any recognized GitHub URL form.

    Accepted forms:
    - https://github.com/owner/repo
    - https://github.com/owner/repo.git
    - github.com/owner/repo
    - git@github.com:owner/repo.git
    - owner/repo  (shorthand)

    Returns None if the URL is not recognizable.
    """
    url = url.strip()

    for pattern in (_GITHUB_SSH_RE, _GITHUB_HTTPS_RE, _SHORTHAND_RE):
        m = pattern.match(url)
        if m:
            return m.group("owner"), m.group("repo")

    return None


def _normalize_to_https(owner: str, repo: str) -> str:
    return f"https://github.com/{owner}/{repo}"


def _inject_token(url: str, token: str) -> str:
    """Insert a PAT into an HTTPS GitHub URL for authenticated clones."""
    if url.startswith("https://"):
        return url.replace("https://", f"https://{token}@", 1)
    return url


def _temp_clone_dir(repo_name: str) -> str:
    """Build a predictable temp directory path for a clone."""
    ts = int(time.time())
    return f"/tmp/audit_github_{repo_name}_{ts}"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class GitHubIntegration:
    """
    High-level GitHub integration: clone repositories, fetch metadata,
    list Python files, and validate URLs.
    """

    def __init__(self, token: str | None = None) -> None:
        """
        Parameters
        ----------
        token:
            GitHub Personal Access Token. Falls back to the GITHUB_TOKEN
            environment variable when not supplied.
        """
        self._token: str | None = token or os.environ.get("GITHUB_TOKEN") or None
        self._gh: Optional[object] = None  # lazy-initialised PyGithub client
        # Track temp dirs so we can clean them up on error
        self._managed_dirs: list[str] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_gh_client(self) -> "Github":
        """Return a cached PyGithub client, creating it on first call."""
        if not _PYGITHUB_AVAILABLE:
            raise GitHubError(
                "PyGithub is not installed. "
                "Add 'PyGithub>=2.1.0' to requirements-github.txt and reinstall."
            )
        if self._gh is None:
            if self._token:
                auth = GithubAuth.Token(self._token)
                self._gh = Github(auth=auth)
            else:
                self._gh = Github()
        return self._gh  # type: ignore[return-value]

    def _fetch_gh_repo(self, owner: str, repo: str) -> "object":
        """
        Fetch a PyGithub Repository object.

        Raises a user-friendly GitHubError on common failure modes.
        """
        gh = self._get_gh_client()
        try:
            return gh.get_repo(f"{owner}/{repo}")
        except GithubException as exc:
            status = getattr(exc, "status", None)
            if status == 401:
                raise GitHubAuthError(
                    "GitHub authentication failed. "
                    "Check that GITHUB_TOKEN is correct and has 'repo' scope."
                ) from exc
            if status == 403:
                # Could be rate-limit or forbidden
                data = getattr(exc, "data", {}) or {}
                msg = data.get("message", "")
                if "rate limit" in msg.lower():
                    raise GitHubRateLimitError(
                        "GitHub API rate limit exceeded. "
                        "Provide a GITHUB_TOKEN to raise the limit to 5 000 req/hr."
                    ) from exc
                raise GitHubAuthError(
                    "Access to this repository is forbidden. "
                    "It may be private — supply a GITHUB_TOKEN with 'repo' scope."
                ) from exc
            if status == 404:
                raise GitHubError(
                    f"Repository '{owner}/{repo}' not found on GitHub. "
                    "Check the URL and ensure the repo is public (or supply a token)."
                ) from exc
            raise GitHubError(f"GitHub API error {status}: {exc}") from exc

    @staticmethod
    def _repo_to_info(gh_repo: "object") -> RepoInfo:
        """Convert a PyGithub Repository to our RepoInfo TypedDict."""
        return RepoInfo(
            name=gh_repo.name,  # type: ignore[attr-defined]
            full_name=gh_repo.full_name,  # type: ignore[attr-defined]
            description=gh_repo.description or "",  # type: ignore[attr-defined]
            default_branch=gh_repo.default_branch or "main",  # type: ignore[attr-defined]
            language=gh_repo.language or "",  # type: ignore[attr-defined]
            stars=gh_repo.stargazers_count,  # type: ignore[attr-defined]
            size_kb=gh_repo.size,  # type: ignore[attr-defined]
            clone_url=gh_repo.clone_url,  # type: ignore[attr-defined]
            topics=gh_repo.get_topics(),  # type: ignore[attr-defined]
            is_private=gh_repo.private,  # type: ignore[attr-defined]
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_url(self, url: str) -> tuple[bool, str]:
        """
        Validate and normalise a GitHub repository URL.

        Returns
        -------
        (is_valid, normalized_url)
            normalized_url is the canonical https://github.com/owner/repo form,
            or the original string if parsing fails.
        """
        parsed = _parse_github_url(url)
        if parsed is None:
            return False, url
        owner, repo = parsed
        return True, _normalize_to_https(owner, repo)

    def get_repo_info(self, repo_url: str) -> RepoInfo:
        """
        Fetch repository metadata via the GitHub API (no clone required).

        Parameters
        ----------
        repo_url:
            Any supported GitHub URL form.

        Returns
        -------
        RepoInfo
            Structured metadata dict.

        Raises
        ------
        GitHubError
            With a user-friendly message on any failure.
        """
        parsed = _parse_github_url(repo_url)
        if parsed is None:
            raise GitHubError(
                f"Cannot parse '{repo_url}' as a GitHub URL. "
                "Expected https://github.com/owner/repo or owner/repo shorthand."
            )
        owner, repo = parsed
        gh_repo = self._fetch_gh_repo(owner, repo)
        return self._repo_to_info(gh_repo)

    def list_python_files(
        self,
        repo_url: str,
        branch: str | None = None,
    ) -> list[str]:
        """
        List all Python (.py) files in a repository via the GitHub Contents API.

        This does *not* clone the repository — useful for a quick preview before
        committing to a full clone + audit.

        Parameters
        ----------
        repo_url:
            Any supported GitHub URL form.
        branch:
            Branch/ref to search.  Defaults to the repository's default branch.

        Returns
        -------
        list[str]
            Sorted list of repo-relative file paths, e.g. ``["src/app.py", …]``.
        """
        parsed = _parse_github_url(repo_url)
        if parsed is None:
            raise GitHubError(f"Cannot parse '{repo_url}' as a GitHub URL.")
        owner, repo = parsed
        gh_repo = self._fetch_gh_repo(owner, repo)

        ref = branch or gh_repo.default_branch  # type: ignore[attr-defined]

        try:
            git_tree = gh_repo.get_git_tree(ref, recursive=True)  # type: ignore[attr-defined]
        except GithubException as exc:
            raise GitHubError(
                f"Could not retrieve file tree for branch '{ref}': {exc}"
            ) from exc

        py_files: list[str] = []
        for element in git_tree.tree:
            if element.type == "blob" and element.path.endswith(".py"):
                py_files.append(element.path)

        return sorted(py_files)

    def clone_repo(
        self,
        repo_url: str,
        branch: str | None = None,
        dest_dir: str | None = None,
    ) -> CloneResult:
        """
        Clone a GitHub repository (shallow, depth=1) to a local directory.

        Workflow
        --------
        1. Validate and normalise the URL.
        2. If a token is available, verify the repo via the API and check
           that it is a Python project (language == "Python").
        3. Build the authenticated clone URL (token injected into HTTPS URL).
        4. Run ``git clone`` via subprocess (reliable, supports large repos).
        5. Return a :class:`CloneResult` with the local path and metadata.

        The temp directory is tracked internally and can be cleaned up with
        :meth:`cleanup_clone`.

        Parameters
        ----------
        repo_url:
            Any supported GitHub URL form.
        branch:
            Branch to clone.  Defaults to the repository's default branch.
        dest_dir:
            Target directory.  Created if it does not exist.
            Defaults to ``/tmp/audit_github_{repo_name}_{timestamp}/``.

        Returns
        -------
        CloneResult

        Raises
        ------
        GitHubError
            With a user-friendly message on any failure.
        GitHubAuthError
            When the repo is private but no token is available.
        GitHubNotPythonError
            When the GitHub-detected language is not Python (and the API is
            reachable).
        """
        parsed = _parse_github_url(repo_url)
        if parsed is None:
            raise GitHubError(
                f"Cannot parse '{repo_url}' as a GitHub URL. "
                "Expected https://github.com/owner/repo, git@github.com:owner/repo, "
                "or owner/repo shorthand."
            )
        owner, repo_name = parsed
        normalized_url = _normalize_to_https(owner, repo_name)

        # ------------------------------------------------------------------
        # Step 1: Fetch metadata via API (graceful degradation if no token)
        # ------------------------------------------------------------------
        repo_info: RepoInfo | None = None
        try:
            repo_info = self.get_repo_info(normalized_url)
        except GitHubAuthError:
            raise  # propagate auth errors (private repo without token)
        except GitHubError:
            # API unavailable / rate limited — proceed without metadata
            repo_info = None

        # ------------------------------------------------------------------
        # Step 2: Python-project gate (skip if API is unavailable)
        # ------------------------------------------------------------------
        if repo_info is not None:
            lang = repo_info.get("language", "")
            if lang and lang.lower() != "python":
                raise GitHubNotPythonError(
                    f"Repository '{owner}/{repo_name}' is identified as a "
                    f"'{lang}' project on GitHub, not Python. "
                    "This audit tool targets Python codebases. "
                    "If the repo contains Python despite the detected language, "
                    "use --force or pass the path directly."
                )

        # ------------------------------------------------------------------
        # Step 3: Determine effective branch and clone URL
        # ------------------------------------------------------------------
        effective_branch = branch
        if effective_branch is None and repo_info is not None:
            # Only set if we know the actual default branch from the API —
            # falling back to "main" would break repos that use "master" etc.
            effective_branch = repo_info.get("default_branch") or None

        clone_url = normalized_url
        if self._token:
            clone_url = _inject_token(normalized_url, self._token)

        # ------------------------------------------------------------------
        # Step 4: Prepare destination directory
        # ------------------------------------------------------------------
        if dest_dir is None:
            dest_dir = _temp_clone_dir(repo_name)

        dest_path = Path(dest_dir)
        dest_path.mkdir(parents=True, exist_ok=True)
        self._managed_dirs.append(str(dest_path))

        # ------------------------------------------------------------------
        # Step 5: git clone — try with explicit branch, fall back to HEAD
        # The GitHub API's default_branch can lag behind or differ from what
        # git actually sees on the remote (e.g. API says "main", remote has
        # "master"). Always retry without --branch on branch-not-found errors.
        # ------------------------------------------------------------------
        def _run_clone(extra_branch_args: list[str]) -> subprocess.CompletedProcess:
            cmd = ["git", "clone", "--depth", "1"] + extra_branch_args + [clone_url, str(dest_path)]
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                env={**os.environ},
            )

        try:
            if effective_branch:
                result = _run_clone(["--branch", effective_branch])
                if result.returncode != 0 and (
                    "Remote branch" in result.stderr or "not found in upstream" in result.stderr
                ):
                    # Branch name from API doesn't match remote — clone HEAD instead
                    shutil.rmtree(str(dest_path), ignore_errors=True)
                    dest_path.mkdir(parents=True, exist_ok=True)
                    result = _run_clone([])
            else:
                result = _run_clone([])
        except subprocess.TimeoutExpired as exc:
            self._safe_rmtree(str(dest_path))
            raise GitHubError(
                f"git clone timed out after 3 minutes for '{owner}/{repo_name}'. "
                "The repository may be very large. Try cloning a specific branch."
            ) from exc
        except Exception as exc:
            self._safe_rmtree(str(dest_path))
            raise GitHubError(
                f"Unexpected error during git clone: {exc}"
            ) from exc

        if result.returncode != 0:
            self._safe_rmtree(str(dest_path))
            stderr = result.stderr.strip()
            if "Repository not found" in stderr or "does not exist" in stderr:
                raise GitHubError(
                    f"Repository '{owner}/{repo_name}' not found. "
                    "Check the URL and confirm the repository exists."
                )
            if "Authentication failed" in stderr or "Invalid username or password" in stderr:
                raise GitHubAuthError(
                    "Git authentication failed. "
                    "Provide a valid GITHUB_TOKEN with 'repo' scope for private repositories."
                )
            raise GitHubError(
                f"git clone failed for '{owner}/{repo_name}': {stderr}"
            )

        # ------------------------------------------------------------------
        # Step 6: Assemble CloneResult
        # ------------------------------------------------------------------
        if repo_info is not None:
            return CloneResult(
                path=str(dest_path),
                repo_name=repo_name,
                full_name=repo_info["full_name"],
                description=repo_info["description"],
                default_branch=repo_info["default_branch"],
                language=repo_info["language"],
                stars=repo_info["stars"],
                size_kb=repo_info["size_kb"],
                clone_url=repo_info["clone_url"],
                topics=repo_info["topics"],
                is_private=repo_info["is_private"],
            )

        # Fallback when API metadata was unavailable
        return CloneResult(
            path=str(dest_path),
            repo_name=repo_name,
            full_name=f"{owner}/{repo_name}",
            description="",
            default_branch=effective_branch or "main",
            language="Python",
            stars=0,
            size_kb=0,
            clone_url=normalized_url,
            topics=[],
            is_private=False,
        )

    def cleanup_clone(self, path: str) -> None:
        """
        Remove a cloned directory from disk.

        Parameters
        ----------
        path:
            The ``path`` value from a :class:`CloneResult` (or any directory).
        """
        self._safe_rmtree(path)
        try:
            self._managed_dirs.remove(path)
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_rmtree(path: str) -> None:
        """Remove a directory tree, ignoring errors."""
        try:
            shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass
