"""Check an installed distribution outside a checkout without live API calls."""

import argparse
import os
import tempfile
import tomllib
from importlib.metadata import distribution
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

import gitinject
from gitinject.cli import cli
from gitinject.gl_runner import GitLabRunner
from gitinject.resources import PACKAGE_DIR, dataset_dir, research_dir
from gitinject.run_record import RunRecord, RunSpec
from gitinject.runner import BenchmarkRunner
from gitinject.scanner.prompt_extractor import extract
from gitinject.scenario_loader import discover_scenario_paths, load_scenario


def check_assets(source: Path, installed: Path) -> int:
    paths = [p for p in source.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"]
    assert paths, f"No source assets found in {source}"
    for path in paths:
        target = installed / path.relative_to(source)
        assert target.is_file(), f"Missing packaged asset: {target}"
        assert target.read_bytes() == path.read_bytes(), f"Packaged asset differs: {target}"
    return len(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-installed", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if args.require_installed:
        assert not Path(gitinject.__file__).resolve().is_relative_to(root / "src"), "Loaded checkout instead of wheel"
    metadata = distribution("gitinject")
    expected_version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    assert metadata.version == expected_version
    assert any(ep.name == "gitinject" and ep.value == "gitinject.cli:cli" for ep in metadata.entry_points)
    assert all(not dep.startswith(("ipykernel", "pre-commit", "pytest")) for dep in metadata.requires or [])
    total = check_assets(root / "src/gitinject", PACKAGE_DIR)
    with tempfile.TemporaryDirectory(prefix="gitinject-smoke-") as temporary:
        previous = Path.cwd()
        os.chdir(temporary)
        try:
            total += check_assets(root / "research/scenarios", research_dir())
            for definition in discover_scenario_paths(dataset_dir("scenarios")):
                scenario = load_scenario(definition, temporary)
                for fixture in scenario.get_required_files().values():
                    assert Path(fixture).is_file(), f"Missing scenario fixture: {fixture}"
            for runner_type in (BenchmarkRunner, GitLabRunner):
                runner = runner_type.__new__(runner_type)
                runner.workspace_dir = temporary
                assert runner._find_scenario_path("vulnerable_code_review")
            assert extract("codex-pr-review").provider == "codex"
            with patch("gitinject.runner.GitHubClient", side_effect=AssertionError("Unexpected authentication")):
                for args in (
                    ["--help"],
                    ["list", "workflows"],
                    ["list", "scenarios"],
                    ["run-suite", "--workflow-labels", "codex", "--scenario-type", "benign", "--dry-run"],
                ):
                    result = CliRunner().invoke(cli, args)
                    assert result.exit_code == 0, result.output
                    assert result.output.strip(), f"Empty CLI output: {args}"
            assert not list(Path(temporary).iterdir()), "Discovery wrote to the workspace"
            record = RunRecord(temporary, RunSpec(workflow="codex-pr-review", scenario="vulnerable_code_review"))
            assert record.directory.parent == Path(temporary) / "runs"
        finally:
            os.chdir(previous)
    print(f"GitInject {metadata.version}: installed CLI, API, workspace output, and {total} packaged files verified")


if __name__ == "__main__":
    main()
