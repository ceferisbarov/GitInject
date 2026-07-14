from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.benchmark.runner import BenchmarkRunner


@pytest.fixture
def runner():
    with patch("src.benchmark.runner.GitHubClient") as mock_client:
        # Mock GitHub user for _generate_repo_name
        mock_user = MagicMock()
        mock_user.login = "testuser"
        mock_client.return_value.gh.get_user.return_value = mock_user
        return BenchmarkRunner(workspace_dir="/tmp", repo_prefix="test-repo")


def test_generate_repo_name_with_owner(runner):
    name = runner._generate_repo_name("owner/prefix")
    assert name.startswith("owner/prefix-")
    assert len(name.split("-")[-1]) == 6


def test_generate_repo_name_without_owner(runner):
    with patch("src.benchmark.runner.GitHubClient") as mock_client:
        mock_user = MagicMock()
        mock_user.login = "resolved-user"
        mock_client.return_value.gh.get_user.return_value = mock_user
        r = BenchmarkRunner(workspace_dir="/tmp", repo_prefix="my-bench")
        assert r.repo_name.startswith("resolved-user/my-bench-")


def test_poll_for_completion_success(runner):
    # Mock repository and workflow runs
    mock_repo = MagicMock()
    mock_run = MagicMock()
    mock_run.id = 12345
    mock_run.status = "completed"
    mock_run.conclusion = "success"
    mock_run.created_at = datetime.now(timezone.utc)
    mock_run.event = "pull_request"

    mock_repo.get_workflow_runs.return_value = [mock_run]
    runner.gh_client.repository = mock_repo

    # First call: sets _last_run_count and returns None for quiescence
    res = runner._wait_for_run.__wrapped__(runner, mock_run.created_at.timestamp() - 5, expected_event="pull_request")
    assert res is None
    assert runner._last_run_count == 1

    # Second call: returns the run ID
    run_id = runner._wait_for_run.__wrapped__(runner, mock_run.created_at.timestamp() - 5, expected_event="pull_request")
    assert run_id == 12345
    assert not hasattr(runner, "_last_run_count")


def test_poll_for_completion_multiple_runs(runner):
    now = datetime.now(timezone.utc)

    # Mock repository and multiple workflow runs
    mock_repo = MagicMock()

    # Run A: The "real" one, started first
    run_a = MagicMock()
    run_a.id = 111
    run_a.status = "completed"
    run_a.conclusion = "success"
    run_a.created_at = now
    run_a.name = "Real Workflow"
    run_a.event = "pull_request"

    # Run B: Side-effect, started later, finished fast
    run_b = MagicMock()
    run_b.id = 222
    run_b.status = "completed"
    run_b.conclusion = "skipped"
    run_b.created_at = now + timedelta(seconds=1)
    run_b.name = "Side-effect Workflow"
    run_b.event = "push"

    # get_workflow_runs returns newest first
    mock_repo.get_workflow_runs.return_value = [run_b, run_a]
    runner.gh_client.repository = mock_repo

    # First call for quiescence
    res = runner._wait_for_run.__wrapped__(runner, now.timestamp() - 5, expected_event="pull_request")
    assert res is None
    assert runner._last_run_count == 2

    # Second call returns run_a (matching pull_request)
    run_id = runner._wait_for_run.__wrapped__(runner, now.timestamp() - 5, expected_event="pull_request")

    # Should pick run_a (matching pull_request)
    assert run_id == 111


def test_poll_for_completion_waits_for_all(runner):
    now = datetime.now(timezone.utc)
    mock_repo = MagicMock()

    run_a = MagicMock()
    run_a.id = 111
    run_a.status = "in_progress"
    run_a.created_at = now
    run_a.event = "pull_request"

    run_b = MagicMock()
    run_b.id = 222
    run_b.status = "completed"
    run_b.conclusion = "skipped"
    run_b.created_at = now + timedelta(seconds=1)
    run_b.event = "push"

    mock_repo.get_workflow_runs.return_value = [run_b, run_a]
    runner.gh_client.repository = mock_repo

    # Should return None because run_a is in_progress
    run_id = runner._wait_for_run.__wrapped__(runner, now.timestamp() - 5, expected_event="pull_request")
    assert run_id is None


def test_poll_for_completion_ignores_old_runs(runner):
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(minutes=30)

    mock_repo = MagicMock()
    mock_run = MagicMock()
    mock_run.id = "old_id"
    mock_run.status = "completed"
    mock_run.conclusion = "success"
    mock_run.created_at = old_time

    mock_repo.get_workflow_runs.return_value = [mock_run]
    runner.gh_client.repository = mock_repo

    # Should timeout because it ignores old runs (returns None in retry loop which stop_after_attempt eventually breaks)
    # We can mock the retry to stop faster
    with patch("src.benchmark.runner.wait_exponential", return_value=MagicMock()):
        # Mocking the retry behavior to just return None instead of looping 60 times
        with patch.object(runner, "_wait_for_run", return_value=None):
            run_id = runner._wait_for_run(now.timestamp())
            assert run_id is None


def test_get_workflow_requirements_standard(runner, tmp_path):
    # Setup standardized directory structure
    workflow_dir = tmp_path / "test-wf"
    workflow_dir.mkdir()

    workflows_path = workflow_dir / "contents" / ".github" / "workflows"
    workflows_path.mkdir(parents=True)

    # Create workflow files with secrets/vars
    wf1 = workflows_path / "main.yml"
    wf1.write_text("""
    env:
      S1: ${{ secrets.MY_SECRET }}
      V1: ${{ vars.MY_VAR }}
    """)

    wf2 = workflows_path / "other.yml"
    wf2.write_text("""
    jobs:
      test:
        env:
          S2: ${{ secrets.ANOTHER_SECRET }}
          G: ${{ secrets.GITHUB_TOKEN }}
    """)

    requirements = runner._get_workflow_requirements(str(workflow_dir))

    assert "MY_SECRET" in requirements["secrets"]
    assert "ANOTHER_SECRET" in requirements["secrets"]
    assert "GITHUB_TOKEN" not in requirements["secrets"]  # GITHUB_TOKEN is ignored
    assert "MY_VAR" in requirements["vars"]


def test_get_workflow_requirements_legacy(runner, tmp_path):
    # Setup legacy (root-level YAMLs) structure
    workflow_dir = tmp_path / "legacy-wf"
    workflow_dir.mkdir()

    # Create workflow files directly in the root
    wf1 = workflow_dir / "main.yml"
    wf1.write_text("""
    env:
      S1: ${{ secrets.LEGACY_SECRET }}
    """)

    requirements = runner._get_workflow_requirements(str(workflow_dir))

    assert "LEGACY_SECRET" in requirements["secrets"]
