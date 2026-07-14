import uuid

import click
import pytest

from src.benchmark.utils.gh_client import GitHubClient
from src.benchmark.utils.provisioner import RepoProvisioner


@pytest.fixture(scope="module")
def real_gh_client(repo_owner):
    """Fixture to provide a real GitHubClient for a temporary repository."""
    repo_name = f"temp-test-provisioner-{uuid.uuid4().hex[:8]}"
    full_repo = f"{repo_owner}/{repo_name}"
    client = GitHubClient(repo=full_repo)

    yield client

    # Cleanup: Delete the repository
    success, err = client.delete_repo()
    if not success and err and "delete_repo" in err:
        click.echo(click.style(f"\nWARNING: Could not delete repository {full_repo} due to missing scope.\n", fg="yellow"))
    elif not success:
        click.echo(click.style(f"\nERROR: Could not delete repository {full_repo}: {err}\n", fg="red"))


def test_provisioner_real_provision(real_gh_client, tmp_path):
    """Real integration test for RepoProvisioner.provision."""
    provisioner = RepoProvisioner(real_gh_client)

    # Create a dummy workflow directory structure
    workflow_dir = tmp_path / "test-workflow"
    contents_dir = workflow_dir / "contents" / ".github" / "workflows"
    contents_dir.mkdir(parents=True)
    workflow_file = contents_dir / "ci.yml"
    workflow_content = (
        "name: Test CI\n"
        "on: push\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hello"
    )
    workflow_file.write_text(workflow_content)

    # Create a dummy scenario file
    scenario_file = tmp_path / "scenario.txt"
    scenario_file.write_text("scenario data")

    required_files = {"src/scenario.txt": str(scenario_file), "data/config.json": '{"test": true}'}

    # Run provision
    provisioner.provision(workflow_dir=str(workflow_dir), required_files=required_files, branch="bench-branch")

    # Verify results
    # 1. Workflow and scenario files should be in the target branch (bench-branch)
    files_bench = real_gh_client.list_files(branch="bench-branch")
    assert ".github/workflows/ci.yml" in files_bench
    assert "src/scenario.txt" in files_bench
    assert "data/config.json" in files_bench

    # 2. Default branch (main) should only have README.md (from initial commit)
    files_main = real_gh_client.list_files(branch="main")
    assert "README.md" in files_main


def test_provisioner_real_fork(tmp_path, repo_owner):
    """Real integration test for forking via provisioner."""
    template = "octocat/Spoon-Knife"
    repo_name = f"temp-test-prov-fork-{uuid.uuid4().hex[:8]}"
    full_repo = f"{repo_owner}/{repo_name}"
    client = GitHubClient(repo=full_repo)
    provisioner = RepoProvisioner(client)

    try:
        provisioner.provision(workflow_dir="none", template_repo=template)

        info = client.get_repo_info()
        assert info.get("name") == repo_name

        files = client.list_files(branch="main")
        assert "README.md" in files or "index.html" in files
    finally:
        provisioner.teardown()
