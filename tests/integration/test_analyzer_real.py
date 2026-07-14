import os
import uuid

import click
import pytest

from src.benchmark.analyzer import BenchmarkAnalyzer
from src.benchmark.utils.gh_client import GitHubClient


@pytest.fixture(scope="module")
def real_analyzer_repo(repo_owner):
    """Fixture to create a temporary real GitHub repository for analyzer tests."""
    repo_name = f"temp-test-analyzer-{uuid.uuid4().hex[:8]}"
    full_repo = f"{repo_owner}/{repo_name}"
    client = GitHubClient(repo=full_repo)

    # 1. Create the repository
    success, err = client.create_repo(public=True)
    if not success:
        pytest.fail(f"Failed to create test repository {full_repo}: {err}")

    # 2. Add an initial commit
    client.put_file("README.md", "# Test", "initial commit", branch="main")

    yield client

    # Cleanup: Delete the repository
    success, err = client.delete_repo()
    if not success and err and "delete_repo" in err:
        click.echo(click.style(f"\nWARNING: Could not delete repository {full_repo} due to missing scope.\n", fg="yellow"))
    elif not success:
        click.echo(click.style(f"\nERROR: Could not delete repository {full_repo}: {err}\n", fg="red"))


def test_analyzer_real_data_check(real_analyzer_repo, tmp_path):
    """
    Test that BenchmarkAnalyzer can correctly use gh_client to
    evaluate security from real GitHub comments.
    """
    analyzer = BenchmarkAnalyzer(workspace_dir=os.getcwd(), repo=real_analyzer_repo.repo_name)

    # 0. Create a feature branch so we have a diff
    real_analyzer_repo.create_branch("feature-analyzer", source_branch="main")
    real_analyzer_repo.put_file("src/test.txt", "content", "add file", branch="feature-analyzer")

    # 1. Create a PR
    stdout, stderr = real_analyzer_repo.run_gh(
        [
            "pr",
            "create",
            "--title",
            "Analyzer Test PR",
            "--body",
            "Testing analyzer",
            "--head",
            "feature-analyzer",
            "--base",
            "main",
        ]
    )

    if not stdout:
        pytest.fail(f"PR creation failed: {stderr}")

    pr_number = stdout.strip().split("/")[-1]

    # 2. Add a 'malicious' comment with the canary token
    from src.benchmark.scenarios.malicious.pr_injection_exfiltration.scenario import PRInjectionExfiltration

    scenario = PRInjectionExfiltration(workspace_dir=os.getcwd())

    real_analyzer_repo.run_gh(["pr", "comment", pr_number, "--body", f"Here is the secret: {scenario.canary_value}"])

    scenario.runtime_state["pr_number"] = int(pr_number)

    # 4. Analyze
    run_result = {"stdout": "", "stderr": "", "exit_code": 0}
    analysis = analyzer.analyze(run_result, scenario)

    assert analysis["security_breached"] is True
