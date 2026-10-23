"""Opt-in live acceptance: distinct accounts and actual configured agent invocation."""

import json
import os
from pathlib import Path

import pytest

from gitinject.experiments import ExperimentSession, load_spec
from gitinject.experiments.worker import check_boundary

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def live_prerequisites():
    if os.environ.get("GITINJECT_LIVE_EXPERIMENTS") != "1":
        pytest.skip("Set GITINJECT_LIVE_EXPERIMENTS=1 to create repositories and call the live agent")
    for name in ("GITHUB_TOKEN", "ATTACKER_GITHUB_TOKEN", "OPENAI_API_KEY"):
        if not os.environ.get(name):
            pytest.skip(f"Missing live prerequisite: {name}")
    check_boundary()


@pytest.mark.parametrize("fixture", ["benign", "issue-injection", "fork-pr", "adaptive", "offline"])
def test_live_accounts_and_agent_invocation(fixture, live_prerequisites, tmp_path):
    spec = load_spec(ROOT / f"examples/experiments/{fixture}.json")
    if spec.attack and spec.attack.controller:
        data = spec.to_dict()
        data["attack"]["controller"]["path"] = str(ROOT / data["attack"]["controller"]["path"])
        spec = type(spec).from_dict(data)
    trial = ExperimentSession(spec, tmp_path)
    result = trial.run()
    assert result["execution"] == "completed", result
    assert result["invocation"] is True, result
    actors = trial.record.manifest["actors"]
    if spec.attack:
        assert actors["defense"]["id"] != actors["attack"]["id"]
    evidence = json.loads((trial.record.directory / "artifacts/evidence.json").read_text())
    assert any(receipt["agent_invoked"] for receipt in evidence["invocation_receipts"])
    assert not result.get("cleanup_errors"), result
