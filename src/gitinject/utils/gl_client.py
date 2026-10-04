import os
import time

import click
import gitlab
import gitlab.exceptions


class GitLabClient:
    """Thin wrapper around python-gitlab for benchmark provisioning and evaluation."""

    def __init__(self, token: str | None = None, url: str = "https://gitlab.com"):
        token = token or os.environ.get("GITLAB_TOKEN")
        if not token:
            click.echo(
                click.style("Error: GITLAB_TOKEN not set.", fg="red"),
                err=True,
            )
            raise RuntimeError("Missing GitLab authentication")
        self.gl = gitlab.Gitlab(url, private_token=token)
        self.project = None

    def create_project(
        self,
        name: str,
        namespace_path: str | None = None,
        visibility: str = "public",
    ):
        kwargs: dict = {"name": name, "visibility": visibility, "initialize_with_readme": True}
        if namespace_path:
            results = self.gl.namespaces.list(search=namespace_path)
            if results:
                kwargs["namespace_id"] = results[0].id
        self.project = self.gl.projects.create(kwargs)
        return self.project

    def delete_project(self) -> None:
        if self.project:
            try:
                self.project.delete()
            except gitlab.exceptions.GitlabDeleteError as e:
                click.echo(click.style(f"Warning: failed to delete project: {e}", fg="yellow"))
            self.project = None

    def push_files(self, branch: str, files: dict[str, str], commit_message: str = "add files") -> None:
        """Batch-commit multiple files to a branch in a single commit."""
        if not files:
            return
        existing = set()
        try:
            tree = self.project.repository_tree(ref=branch, recursive=True, all=True)
            existing = {item["path"] for item in tree}
        except gitlab.exceptions.GitlabGetError:
            pass

        actions = []
        for path, content in files.items():
            action = "update" if path in existing else "create"
            actions.append({"action": action, "file_path": path, "content": content})

        self.project.commits.create(
            {
                "branch": branch,
                "commit_message": commit_message,
                "actions": actions,
            }
        )

    def create_branch(self, name: str, ref: str = "main") -> None:
        try:
            self.project.branches.create({"branch": name, "ref": ref})
        except gitlab.exceptions.GitlabCreateError:
            pass  # Branch already exists

    def create_merge_request(
        self,
        source_branch: str,
        target_branch: str,
        title: str,
        description: str = "",
    ) -> int:
        mr = self.project.mergerequests.create(
            {
                "source_branch": source_branch,
                "target_branch": target_branch,
                "title": title,
                "description": description,
            }
        )
        return mr.iid

    def get_mr_notes(self, mr_iid: int) -> list[str]:
        mr = self.project.mergerequests.get(mr_iid)
        notes = mr.notes.list(all=True)
        return [n.body for n in notes if not n.system]

    def get_mr_pipelines(self, mr_iid: int) -> list:
        mr = self.project.mergerequests.get(mr_iid)
        return mr.pipelines.list()

    def wait_for_pipeline(self, pipeline_id: int, timeout_s: int = 600, poll_interval: int = 15) -> str:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            pipeline = self.project.pipelines.get(pipeline_id)
            if pipeline.status not in ("created", "waiting_for_resource", "preparing", "pending", "running", "scheduled"):
                return pipeline.status
            click.echo(f"  Pipeline {pipeline_id} status: {pipeline.status}...")
            time.sleep(poll_interval)
        return "timeout"

    def set_variable(self, key: str, value: str, masked: bool = True, protected: bool = False) -> None:
        try:
            var = self.project.variables.get(key)
            var.value = value
            var.save()
        except gitlab.exceptions.GitlabGetError:
            self.project.variables.create(
                {
                    "key": key,
                    "value": value,
                    "masked": masked,
                    "protected": protected,
                }
            )

    def get_project_url(self) -> str | None:
        return self.project.web_url if self.project else None

    def get_default_branch(self) -> str:
        if self.project:
            return self.project.default_branch or "main"
        return "main"
