import logging
import os
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import click
import requests
from github import Github, GithubException, InputGitTreeElement, Repository
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple rate limiter to prevent hitting GitHub secondary rate limits."""

    def __init__(self):
        max_calls = os.environ.get("GITHUB_MAX_CALLS_PER_MINUTE", 20)
        self.enabled = max_calls is not None
        if self.enabled:
            self.delay = 60.0 / float(max_calls)
            self.last_call = 0.0

    def wait(self):
        if not self.enabled:
            return
        now = time.time()
        elapsed = now - self.last_call
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_call = time.time()


rate_limiter = RateLimiter()


class GitHubClient:
    """A wrapper for PyGitHub to interact with repositories."""

    def __init__(
        self,
        repo: str = "owner/repo",
        token: Optional[str] = None,
        token_env_var: str = "GITHUB_TOKEN",
        auth_label: str = "GitHub",
        record_event=None,
        actor: str = "owner",
    ):
        self.repo_name = repo
        self.token_env_var = token_env_var
        self.auth_label = auth_label
        self.token = token or self._get_token()
        self.gh = Github(self.token)
        self._repo_cache: Optional[Repository.Repository] = None
        self._owned_repo = None
        self._authenticated_login = None
        self.record_event = record_event
        self.actor = actor

    def _record(self, kind, **data):
        if self.record_event is not None:
            self.record_event(kind, actor=self.actor, **data)

    def request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Call any GitHub REST endpoint, preserving the response and HTTP errors."""
        base = self.gh.base_url.rstrip("/")
        url = endpoint if endpoint.startswith("https://") else base + "/" + endpoint.lstrip("/")
        parsed, origin = urlsplit(url), urlsplit(base)
        if parsed.scheme != "https" or parsed.netloc != origin.netloc or parsed.username or parsed.password:
            raise ValueError("Endpoint must belong to the authenticated GitHub API host")
        headers = requests.structures.CaseInsensitiveDict(kwargs.pop("headers", {}))
        if "Authorization" in headers or "auth" in kwargs:
            raise ValueError("Select a GitHub actor instead of overriding its credentials")
        headers["Authorization"] = f"Bearer {self.token}"
        headers.setdefault("Accept", "application/vnd.github+json")
        kwargs.setdefault("timeout", 60)
        kwargs.setdefault("allow_redirects", False)
        request_id = uuid.uuid4().hex
        self._record("api_request", request_id=request_id, method=method.upper(), path=parsed.path)
        try:
            response = requests.request(method, url, headers=headers, **kwargs)
        except requests.RequestException:
            self._record("api_response", request_id=request_id, status=None)
            raise
        self._record(
            "api_response",
            request_id=request_id,
            status=response.status_code,
            github_request_id=response.headers.get("X-GitHub-Request-Id"),
        )
        response.raise_for_status()
        return response

    def graphql(self, query: str, variables: dict | None = None) -> dict:
        result = self.request("POST", "/graphql", json={"query": query, "variables": variables or {}}).json()
        if result.get("errors"):
            raise RuntimeError(f"GitHub GraphQL errors: {result['errors']}")
        return result["data"]

    def _claim_repository(self, repo):
        self._owned_repo = (repo.full_name, repo.id)
        self._record("resource", name=repo.full_name, id=repo.id, state="created")

    def _get_token(self) -> str:
        """Retrieves GitHub token from environment or gh CLI."""
        token = os.environ.get(self.token_env_var)
        if token:
            return token

        if self.token_env_var == "GITHUB_TOKEN":
            try:
                result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True)
                return result.stdout.strip()
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

        click.echo(
            click.style(
                f"Error: {self.auth_label} token not found. Please set {self.token_env_var}"
                + (" or run 'gh auth login'." if self.token_env_var == "GITHUB_TOKEN" else "."),
                fg="red",
            ),
            err=True,
        )
        raise RuntimeError("Missing GitHub authentication")

    def get_authenticated_user_login(self) -> str:
        """Returns the login of the authenticated user for this client."""
        if self._authenticated_login is None:
            rate_limiter.wait()
            self._authenticated_login = self.gh.get_user().login
        return self._authenticated_login

    @property
    def repository(self) -> Repository.Repository:
        """Lazily loads and returns the Repository object."""
        if self._repo_cache is None:
            rate_limiter.wait()
            self._repo_cache = self.gh.get_repo(self.repo_name)
        return self._repo_cache

    def get_repo_info(self) -> Optional[Dict[str, Any]]:
        """Fetches repository information."""
        try:
            repo = self.repository
            return {
                "name": repo.name,
                "owner": {"login": repo.owner.login},
                "defaultBranchRef": {"name": repo.default_branch},
                "isEmpty": repo.size == 0,
                "size": repo.size,
                "default_branch": repo.default_branch,
            }
        except GithubException as e:
            if e.status == 404:
                return None
            raise

    def get_default_branch(self) -> str:
        """Returns the name of the default branch."""
        try:
            return self.repository.default_branch
        except GithubException:
            return "main"

    def create_repo(self, public: bool = True) -> Tuple[bool, str]:
        """Creates the repository if it doesn't exist."""
        if self._owned_repo is not None:
            return False, "Client already owns a repository awaiting cleanup"
        try:
            name = self.repo_name.split("/")[-1]
            if "/" in self.repo_name:
                owner = self.repo_name.split("/", 1)[0]
                user = self.gh.get_user()
                if user.login.lower() == owner.lower():
                    repo = user.create_repo(name, private=not public)
                else:
                    org = self.gh.get_organization(owner)
                    repo = org.create_repo(name, private=not public)
            else:
                repo = self.gh.get_user().create_repo(name, private=not public)

            self.repo_name = repo.full_name
            self._repo_cache = repo
            self._claim_repository(repo)
            return True, ""
        except GithubException as e:
            return False, str(e)

    def fork_repo(self, template_repo_name: str) -> Tuple[bool, str]:
        """Fork the specified source, refusing collisions and existing owner forks."""
        if self._owned_repo is not None:
            return False, "Client already owns a repository awaiting cleanup"
        try:
            user_login = self.get_authenticated_user_login()
            owner, name = self.repo_name.split("/", 1) if "/" in self.repo_name else (user_login, self.repo_name)
            target = f"{owner}/{name}"
            try:
                self.gh.get_repo(target)
            except GithubException as exc:
                if exc.status != 404:
                    raise
            else:
                return False, f"Repository already exists: {target}"
            template = self.gh.get_repo(template_repo_name)
            for existing in template.get_forks():
                if existing.owner.login.lower() == owner.lower():
                    return False, f"Owner already has a fork: {existing.full_name}; use a separate owner or repository copy"
            kwargs = {"name": name, "default_branch_only": True}
            if owner.lower() != user_login.lower():
                kwargs["organization"] = owner
            new_repo = template.create_fork(**kwargs)
            if new_repo.full_name.lower() != target.lower():
                return False, f"GitHub returned an unexpected fork: {new_repo.full_name}"
            self.repo_name = new_repo.full_name
            self._repo_cache = new_repo
            self._claim_repository(new_repo)
            return True, ""
        except Exception as exc:
            return False, str(exc)

    @retry(
        retry=retry_if_exception_type(GithubException),
        stop=stop_after_attempt(15),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    def wait_until_ready(self):
        repo = self.gh.get_repo(self.repo_name)
        repo.get_branch(repo.default_branch)
        self._repo_cache = repo

    def _delete_repository(self, name: str, repository_id: int) -> None:
        """Delete a recorded repository identity; an absent repository is already clean."""
        try:
            repo = self.gh.get_repo(name)
            if repo.id != repository_id:
                raise RuntimeError(f"Refusing cleanup: repository ID changed for {name}")
            repo.delete()
        except GithubException as exc:
            if exc.status != 404:
                raise

    def delete_owned_repo(self) -> Tuple[bool, str]:
        """Delete only the exact repository created through this client."""
        if self._owned_repo is None:
            return True, ""
        name, repo_id = self._owned_repo
        try:
            self._delete_repository(name, repo_id)
        except (GithubException, RuntimeError) as exc:
            return False, str(exc)
        self._record("resource", name=name, id=repo_id, state="deleted")
        self._owned_repo = None
        self._repo_cache = None
        return True, ""

    @retry(
        retry=retry_if_exception_type(GithubException),
        stop=stop_after_attempt(10),
        wait=wait_exponential(multiplier=2, min=4, max=30),
    )
    def delete_repo(self) -> Tuple[bool, str]:
        """Deletes the current repository."""
        try:
            repo = self.repository
            repo.delete()
            if self._owned_repo == (self.repo_name, repo.id):
                self._owned_repo = None
            self._repo_cache = None
            return True, ""
        except GithubException as e:
            if e.status == 404:
                return True, ""  # Already gone
            if e.status == 403:
                if "delete_repo" in str(e):
                    msg = (
                        "\nERROR: Missing 'delete_repo' scope. Please run:\n  gh auth refresh -h github.com -s delete_repo\n"
                    )
                    click.echo(click.style(msg, fg="yellow", bold=True))
                elif "done being created on disk" in str(e):
                    # Re-raise to let the retry decorator handle it
                    raise e
            return False, str(e)

    def get_branch_info(self, branch_name: str) -> Optional[Dict[str, Any]]:
        """Checks if a branch exists and returns its info."""
        try:
            branch = self.repository.get_branch(branch_name)
            return {"name": branch.name, "commit": {"sha": branch.commit.sha}}
        except GithubException as e:
            if e.status == 404:
                return None
            raise

    def create_branch(self, new_branch: str, source_branch: Optional[str] = None) -> Tuple[bool, str]:
        """Creates a new branch from a source branch."""
        if not source_branch:
            source_branch = self.get_default_branch()

        try:
            sb = self.repository.get_branch(source_branch)
            self.repository.create_git_ref(ref=f"refs/heads/{new_branch}", sha=sb.commit.sha)
            return True, ""
        except GithubException as e:
            return False, str(e)

    def get_file_sha(self, path: str, branch: Optional[str] = None) -> Optional[str]:
        """Gets the SHA of a file on a specific branch."""
        try:
            kwargs = {}
            if branch:
                kwargs["ref"] = branch
            content = self.repository.get_contents(path, **kwargs)
            if isinstance(content, list):
                return None
            return content.sha
        except GithubException as e:
            if e.status == 404:
                return None
            raise

    @retry(
        retry=retry_if_exception_type(GithubException),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(5),
        before_sleep=before_sleep_log(logger, logging.INFO),
    )
    def put_file(self, path: str, content: str, message: str, branch: Optional[str] = None) -> Tuple[bool, str]:
        """Uploads or updates a file using the GitHub API."""
        if not branch:
            branch = self.get_default_branch()

        try:
            sha = self.get_file_sha(path, branch)
            if sha:
                self.repository.update_file(path, message, content, sha, branch=branch)
            else:
                self.repository.create_file(path, message, content, branch=branch)
            return True, ""
        except GithubException as e:
            if e.status == 409:
                raise e
            return False, str(e)

    @retry(
        retry=retry_if_exception_type(GithubException),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(5),
    )
    def delete_file(self, path: str, message: str, branch: Optional[str] = None) -> Tuple[bool, str]:
        """Deletes a file from the repository."""
        if not branch:
            branch = self.get_default_branch()

        try:
            sha = self.get_file_sha(path, branch)
            if sha:
                self.repository.delete_file(path, message, sha, branch=branch)
                return True, ""
            return True, "File not found"  # Already gone
        except GithubException as e:
            return False, str(e)

    @staticmethod
    def _artifact(item, kind):
        created = item.submitted_at if kind == "review" else item.created_at
        return {
            "id": item.id,
            "kind": kind,
            "body": item.body or "",
            "author": item.user.login if item.user else "",
            "author_type": item.user.type if item.user else "",
            "created_at": created.isoformat() if created else None,
            "state": item.state if kind == "review" else None,
        }

    def get_pr_details(self, pr_number: int) -> Dict[str, Any]:
        """Fetch complete, attributed comments and formal reviews; propagate read errors."""
        pr = self.repository.get_pull(pr_number)
        comments = [self._artifact(c, "issue_comment") for c in pr.get_issue_comments()]
        reviews = [self._artifact(r, "review") for r in pr.get_reviews()]
        comments.extend(reviews)
        comments.extend(self._artifact(c, "review_comment") for c in pr.get_review_comments())
        return {
            "title": pr.title,
            "body": pr.body,
            "state": pr.state,
            "comments": [c["body"] for c in comments],
            "comment_details": comments,
            "reviews": reviews,
        }

    def get_issue_details(self, issue_number: int) -> Dict[str, Any]:
        issue = self.repository.get_issue(issue_number)
        comments = [self._artifact(c, "issue_comment") for c in issue.get_comments()]
        return {
            "title": issue.title,
            "body": issue.body,
            "state": issue.state,
            "comments": [c["body"] for c in comments],
            "comment_details": comments,
        }

    @retry(
        retry=retry_if_exception_type(GithubException),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        stop=stop_after_attempt(5),
    )
    def list_files(self, branch: Optional[str] = None) -> List[str]:
        """Lists files in a specific branch."""
        try:
            ref = branch or self.get_default_branch()
            tree = self.repository.get_git_tree(ref, recursive=True)
            return [item.path for item in tree.tree if item.type == "blob"]
        except GithubException as e:
            if e.status == 409:
                return []
            raise

    def set_secret(self, name: str, value: str) -> Tuple[bool, str]:
        """Sets a repository secret."""
        try:
            self.repository.create_secret(name, value)
            return True, ""
        except GithubException as e:
            return False, str(e)

    def set_variable(self, name: str, value: str) -> Tuple[bool, str]:
        """Sets a repository variable."""
        try:
            self.repository.create_variable(name, value)
            return True, ""
        except GithubException as e:
            return False, str(e)

    def enable_actions(self) -> Tuple[bool, str]:
        """Enables GitHub Actions for the repository."""
        try:
            # Using gh CLI for simplicity as PyGitHub doesn't have a direct method for this
            stdout, stderr = self.run_gh(
                ["api", "-X", "PUT", f"repos/{self.repo_name}/actions/permissions", "-F", "enabled=true"]
            )
            if stderr and "error" in stderr.lower():
                return False, stderr
            return True, ""
        except Exception as e:
            return False, str(e)

    def set_fork_pr_approval_policy(self, policy: str = "first_time_contributors_new_to_github") -> Tuple[bool, str]:
        """Sets the fork PR workflow approval policy for the repository."""
        try:
            stdout, stderr = self.run_gh(
                [
                    "api",
                    "-X",
                    "PUT",
                    f"/repos/{self.repo_name}/actions/permissions/fork-pr-contributor-approval",
                    "-H",
                    "X-GitHub-Api-Version: 2026-03-10",
                    "-f",
                    f"approval_policy={policy}",
                ]
            )
            if stderr and "error" in stderr.lower():
                return False, stderr
            return True, ""
        except Exception as e:
            return False, str(e)

    def enable_issues(self) -> Tuple[bool, str]:
        """Enables GitHub Issues for the repository."""
        try:
            # Using gh CLI for simplicity as PyGitHub doesn't have a direct method for this
            stdout, stderr = self.run_gh(["repo", "edit", self.repo_name, "--enable-issues"])
            if stderr:
                return False, stderr
            return True, ""
        except Exception as e:
            return False, str(e)

    def list_repos(self, limit: int = 100) -> List[Dict[str, str]]:
        """Lists repositories for the authenticated user."""
        try:
            repos = self.gh.get_user().get_repos()
            return [{"name": r.name, "nameWithOwner": r.full_name} for r in repos[:limit]]
        except GithubException:
            return []

    def get_workflow_runs(self, workflow_id: str = None) -> List[Any]:
        """Fetches recent runs of a specific workflow or all workflows."""
        try:
            if workflow_id:
                runs = self.repository.get_workflow(workflow_id).get_runs()
            else:
                runs = self.repository.get_workflow_runs()
            return [r for r in runs[:10]]
        except GithubException:
            return []

    def batch_sync(
        self,
        additions: Dict[str, str],
        deletions: List[str],
        message: str,
        branch: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Performs multiple additions and deletions in a single commit."""
        if not branch:
            branch = self.get_default_branch()

        try:
            repo = self.repository

            @retry(
                retry=retry_if_exception_type(GithubException),
                stop=stop_after_attempt(10),
                wait=wait_exponential(multiplier=1, min=2, max=10),
            )
            def get_ref():
                rate_limiter.wait()
                return repo.get_git_ref(f"heads/{branch}")

            ref = get_ref()
            old_commit = repo.get_git_commit(ref.object.sha)
            base_tree_sha = old_commit.tree.sha

            # We avoid recursive=True because it fails with 502 on large repos like Sentry.
            # Instead, we will build the new tree by navigating only what we need.

            def get_tree_without_path(current_tree_sha, path_parts):
                """Recursively navigates trees to 'delete' a path by omitting it from a new tree."""
                tree = repo.get_git_tree(current_tree_sha, recursive=False)
                elements = []

                target = path_parts[0]
                remaining = path_parts[1:]

                found_target = False
                for item in tree.tree:
                    if item.path == target:
                        found_target = True
                        if remaining:
                            # We need to go deeper into this subtree
                            if item.type == "tree":
                                new_subtree_sha = get_tree_without_path(item.sha, remaining)
                                if new_subtree_sha:
                                    elements.append(
                                        InputGitTreeElement(
                                            path=item.path, mode=item.mode, type=item.type, sha=new_subtree_sha
                                        )
                                    )
                                # if new_subtree_sha is None, it means the whole subtree was deleted
                            else:
                                # Target is a file, but we have remaining path parts?
                                # This means the path doesn't match the structure. Keep it as is.
                                elements.append(
                                    InputGitTreeElement(path=item.path, mode=item.mode, type=item.type, sha=item.sha)
                                )

                        else:
                            # This is the item to delete! Just don't add it to elements.
                            pass
                    else:
                        # Not our target, keep it
                        elements.append(InputGitTreeElement(path=item.path, mode=item.mode, type=item.type, sha=item.sha))

                if not found_target:
                    # Target not found in this tree, nothing to delete here
                    return current_tree_sha

                if not elements:
                    # Entire tree is empty now
                    return None

                new_tree = repo.create_git_tree(elements)
                return new_tree.sha

            current_tree_sha = base_tree_sha
            for deletion_path in deletions:
                # Normalize path: remove leading/trailing slashes
                clean_path = deletion_path.strip("/")
                if not clean_path:
                    continue

                path_parts = clean_path.split("/")
                current_tree_sha = get_tree_without_path(current_tree_sha, path_parts)
                if not current_tree_sha:
                    # We deleted everything? (unlikely but possible)
                    # Create an empty tree to avoid errors
                    empty_tree = repo.create_git_tree([])
                    current_tree_sha = empty_tree.sha

            # 2. Handle additions using the base_tree merge capability
            elements = []
            for path, content in additions.items():
                elements.append(InputGitTreeElement(path=path, mode="100644", type="blob", content=content))

            # Create the final tree by merging additions into our modified tree
            final_tree = repo.create_git_tree(elements, base_tree=repo.get_git_tree(current_tree_sha))

            new_commit = repo.create_git_commit(message, final_tree, [old_commit])
            ref.edit(new_commit.sha)

            return True, ""
        except Exception as e:
            return False, str(e)

    def run_gh(self, args, **kwargs):
        """Legacy compatibility method. SHOULD BE REMOVED eventually."""
        cmd = ["gh"] + args
        if kwargs.get("use_repo"):
            cmd += ["-R", self.repo_name]

        env = os.environ.copy()
        env["GH_TOKEN"] = self.token
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            raise RuntimeError(f"gh exited with status {result.returncode}: {result.stderr.strip()}")
        return result.stdout, result.stderr
