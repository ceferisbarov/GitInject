from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from gitinject.cli import cli
from gitinject.gl_runner import GitLabRunner
from gitinject.resources import PACKAGE_DIR, dataset_dir, research_dir
from gitinject.run_record import RunRecord, RunSpec
from gitinject.runner import BenchmarkRunner
from gitinject.scanner.prompt_extractor import extract


def test_bundled_catalogs_work_without_checkout_or_credentials(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("gitinject.runner.GitHubClient", side_effect=AssertionError("Unexpected authentication")):
        for args, expected in (
            (["list", "workflows"], "codex-pr-review"),
            (["list", "scenarios"], "vulnerable_code_review"),
            (["run-suite", "--workflow-labels", "codex", "--scenario-type", "benign", "--dry-run"], "codex-pr-review"),
        ):
            result = CliRunner().invoke(cli, args)
            assert result.exit_code == 0, result.output
            assert expected in result.output
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("layout", ["", "src/gitinject", "src/benchmark"])
def test_workspace_dataset_overrides_bundled_catalog(tmp_path, layout):
    custom = tmp_path / layout / "workflows"
    custom.mkdir(parents=True)
    assert dataset_dir("workflows", tmp_path) == custom
    assert dataset_dir("scenarios", tmp_path) == PACKAGE_DIR / "scenarios"


def test_workspace_datasets_take_precedence_over_checkout(tmp_path):
    for layout in ("", "src/gitinject"):
        (tmp_path / layout / "scenarios").mkdir(parents=True)
    assert dataset_dir("scenarios", tmp_path) == tmp_path / "scenarios"


def test_runners_find_installed_scenarios_and_write_to_workspace(tmp_path):
    for runner_type in (BenchmarkRunner, GitLabRunner):
        runner = runner_type.__new__(runner_type)
        runner.workspace_dir = str(tmp_path)
        runner.repo_name = "owner/example"
        path = runner._find_scenario_path("vulnerable_code_review")
        assert Path(path).is_relative_to(PACKAGE_DIR / "scenarios")
        scenario = runner._load_scenario(path)
        assert scenario.workspace_dir == str(tmp_path)
        assert "examples/tutorial/flaskr/db_utils.py" in scenario.get_required_files()
    record = RunRecord(str(tmp_path), RunSpec(workflow="codex-pr-review", scenario="vulnerable_code_review"))
    assert record.directory.parent == tmp_path / "runs"


def test_prompt_extraction_and_research_notes_work_outside_checkout(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert extract("codex-pr-review").provider == "codex"
    assert (research_dir() / "pr_token_exfiltration_via_git_config.md").is_file()
    override = tmp_path / "research/scenarios"
    override.mkdir(parents=True)
    assert research_dir() == override


def test_unknown_dataset_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="Unknown dataset"):
        dataset_dir("runs", tmp_path)
