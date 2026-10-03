import os
from unittest.mock import MagicMock

import pytest

from src.benchmark.analyzer import BenchmarkAnalyzer
from src.benchmark.evaluators import Evaluator
from src.benchmark.scenarios.benign.vulnerable_code_review.scenario import VulnerableCodeReview


@pytest.fixture
def analyzer():
    return BenchmarkAnalyzer(workspace_dir=os.getcwd(), repo="test/repo")


def test_analyzer_generic_utility_success(analyzer):
    run_result = {
        "stdout": "Some long enough output that should satisfy generic utility check. "
        "It needs to be more than 50 characters long to pass.",
        "stderr": "",
        "exit_code": 0,
        "agent_invoked": True,
    }
    # Pass None as scenario to trigger generic evaluation
    analysis = analyzer.analyze(run_result, None)
    assert analysis["utility_achieved"] is None


def test_analyzer_generic_security_breach(analyzer):
    run_result = {
        "stdout": "I am root:x:0:0:root and I have been pwned",
        "stderr": "",
        "exit_code": 0,
        "agent_invoked": True,
    }
    analysis = analyzer.analyze(run_result, None)
    assert analysis["security_breached"] is None


def test_analyzer_real_scenario_evaluation(analyzer, mocker):
    scenario = VulnerableCodeReview(workspace_dir=os.getcwd())
    run_result = {
        "stdout": "Legitimate code review text here.",
        "stderr": "",
        "exit_code": 0,
        "agent_invoked": True,
    }

    # Mock the evaluators
    mock_utility_evaluator = MagicMock(spec=Evaluator)
    mock_utility_evaluator.evaluate.return_value = True

    mock_security_evaluator = MagicMock(spec=Evaluator)
    mock_security_evaluator.evaluate.return_value = False

    mocker.patch.object(scenario, "get_utility_evaluator", return_value=mock_utility_evaluator)
    mocker.patch.object(scenario, "get_security_evaluator", return_value=mock_security_evaluator)

    analysis = analyzer.analyze(run_result, scenario)

    assert analysis["utility_achieved"] is True
    assert analysis["security_breached"] is False

    mock_utility_evaluator.evaluate.assert_called_once()
    mock_security_evaluator.evaluate.assert_called_once()


@pytest.mark.parametrize("invoked", [False, None])
def test_no_invocation_does_not_prove_resistance(analyzer, mocker, invoked):
    scenario = VulnerableCodeReview("/tmp")
    mocker.patch.object(scenario, "get_utility_evaluator", return_value=MagicMock(evaluate=lambda *args: True))
    mocker.patch.object(scenario, "get_security_evaluator", return_value=MagicMock(evaluate=lambda *args: False))
    analysis = analyzer.analyze({"agent_invoked": invoked, "status": "completed", "conclusion": "skipped"}, scenario)
    assert analysis["utility_achieved"] is None
    assert analysis["security_breached"] is None
    assert analysis["autonomy_achieved"] is invoked


def test_breach_survives_later_workflow_failure_and_utility_error(analyzer, mocker):
    scenario = VulnerableCodeReview("/tmp")
    failed = MagicMock()
    failed.evaluate.side_effect = RuntimeError("judge outage")
    mocker.patch.object(scenario, "get_utility_evaluator", return_value=failed)
    mocker.patch.object(scenario, "get_security_evaluator", return_value=MagicMock(evaluate=lambda *args: True))
    analysis = analyzer.analyze({"agent_invoked": None, "status": "completed", "conclusion": "failure"}, scenario)
    assert analysis["security_breached"] is True
    assert analysis["utility_achieved"] is None
    assert "judge outage" in analysis["evaluation_errors"]["utility_achieved"]
