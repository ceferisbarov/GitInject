import os
import shutil
import uuid

import pytest

from src.benchmark.runner import BenchmarkRunner


@pytest.fixture(scope="module")
def real_runner(repo_owner):
    """Fixture to provide a real BenchmarkRunner with a unique prefix."""
    workspace_dir = os.getcwd()
    prefix = f"{repo_owner}/test-runner-{uuid.uuid4().hex[:6]}"
    runner = BenchmarkRunner(workspace_dir=workspace_dir, repo_prefix=prefix)
    return runner


def test_runner_real_run(real_runner, tmp_path):
    """
    This test executes the full lifecycle of a benchmark run.
    It will create a repo, push a workflow, trigger an event,
    wait for completion, fetch logs, analyze, and delete the repo.
    """
    # 1. Create a temporary workflow for this test
    test_workflow_dir = os.path.join(os.getcwd(), "src/benchmark/workflows/runner-test")
    os.makedirs(os.path.join(test_workflow_dir, "contents", ".github", "workflows"), exist_ok=True)

    workflow_content = """
name: Runner Test
on:
  pull_request:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Integration test run success"
"""
    workflow_file = os.path.join(test_workflow_dir, "contents", ".github", "workflows", "workflow.yml")
    with open(workflow_file, "w") as f:
        f.write(workflow_content)

    metadata_content = (
        '{"name": "Runner Test", "description": "Used for integration testing",'
        ' "category": "code-maintenance", "supported_events": ["pull_request"]}'
    )
    with open(os.path.join(test_workflow_dir, "metadata.json"), "w") as f:
        f.write(metadata_content)

    # 2. Create a dummy scenario file
    scenario_content = """
from src.benchmark.scenario_base import AbstractScenario
from src.benchmark.evaluators import AlwaysPassEvaluator, AlwaysFailEvaluator
from src.benchmark.utils.types import ScenarioType, WorkflowCategory

class TestRunnerScenario(AbstractScenario):
    category = WorkflowCategory.CODE_MAINTENANCE
    scenario_type = ScenarioType.BENIGN
    def __init__(self, workspace_dir):
        super().__init__(workspace_dir)
        self.branch = "feature-test"

    def get_required_files(self): return {"src/code.py": "print('hello')"}
    
    def setup_state(self, gh_client):
        pass

    def teardown_state(self, gh_client): pass
    
    def get_event(self):
        return {
            "event_type": "pull_request",
            "data": {
                "title": "Integration Test PR",
                "body": "Test body",
                "head": self.branch,
                "base": "main"
            }
        }
    def get_utility_evaluator(self): return AlwaysPassEvaluator()
    def get_security_evaluator(self): return AlwaysFailEvaluator()
"""
    scenario_dir = os.path.join(os.getcwd(), "src/benchmark/scenarios/runner_test_scenario")
    os.makedirs(scenario_dir, exist_ok=True)
    scenario_file = os.path.join(scenario_dir, "scenario.py")
    with open(scenario_file, "w") as f:
        f.write(scenario_content)

    try:
        # 3. Run the benchmark
        result = real_runner.run("runner-test", "runner_test_scenario")

        # 4. Assertions
        assert "error" not in result
        assert "analysis" in result
        assert result["analysis"]["utility_achieved"] is True
        assert result["analysis"]["security_breached"] is False
        assert "run_id" in result

        # Verify context snapshot exists
        runs_dir = os.path.join(os.getcwd(), "runs", result["timestamp"].replace(":", "-"))
        assert os.path.exists(os.path.join(runs_dir, "context_snapshot.json"))

    finally:
        # Cleanup local temporary files
        if os.path.exists(test_workflow_dir):
            shutil.rmtree(test_workflow_dir)
        if os.path.exists(scenario_dir):
            shutil.rmtree(scenario_dir)
