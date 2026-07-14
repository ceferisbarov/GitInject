import os
import time

import click

from .gl_client import GitLabClient


class GitLabProvisioner:
    """Handles lifecycle of a GitLab project for benchmarking."""

    def __init__(self, gl_client: GitLabClient):
        self.gl_client = gl_client

    def provision(
        self,
        project_name: str,
        workflow_dir: str,
        required_files: dict | None = None,
        branch: str | None = None,
        variables: dict | None = None,
    ) -> None:
        click.echo(f"Creating GitLab project {project_name}...")
        self.gl_client.create_project(project_name)

        # GitLab needs a moment after initialize_with_readme before branches are writable
        time.sleep(5)

        default_branch = self.gl_client.get_default_branch()

        # Collect workflow files from contents/
        workflow_files: dict[str, str] = {}
        contents_dir = os.path.join(workflow_dir, "contents")
        if os.path.isdir(contents_dir):
            for root, _, filenames in os.walk(contents_dir):
                for filename in filenames:
                    abs_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(abs_path, contents_dir)
                    workflow_files[rel_path] = self._read_file(abs_path)

        if workflow_files:
            click.echo(f"Pushing workflow files to {default_branch}...")
            self.gl_client.push_files(default_branch, workflow_files, "provision: add CI workflow")

        # Create target branch for scenario files (if different from default)
        target_branch = branch or default_branch
        if target_branch != default_branch:
            click.echo(f"Creating branch {target_branch}...")
            self.gl_client.create_branch(target_branch, ref=default_branch)

        # Push scenario-specific files to target branch
        if required_files:
            scenario_files: dict[str, str] = {}
            for repo_path, content_or_path in required_files.items():
                if isinstance(content_or_path, str) and os.path.exists(content_or_path):
                    scenario_files[repo_path] = self._read_file(content_or_path)
                else:
                    scenario_files[repo_path] = str(content_or_path)
            if scenario_files:
                click.echo(f"Pushing scenario files to {target_branch}...")
                self.gl_client.push_files(target_branch, scenario_files, "provision: add scenario files")

        # Set CI/CD variables
        if variables:
            for key, value in variables.items():
                if value:
                    click.echo(f"Setting CI/CD variable '{key}'...")
                    self.gl_client.set_variable(key, value, masked=True)

        click.echo(f"Project ready: {self.gl_client.get_project_url()}")

    def teardown(self) -> None:
        click.echo("Deleting GitLab project...")
        self.gl_client.delete_project()
        click.echo("Project deleted.")

    def _read_file(self, path: str) -> str:
        with open(path, "rb") as f:
            raw = f.read()
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")
