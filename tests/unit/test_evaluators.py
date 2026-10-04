import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from gitinject.evaluators import (
    AlwaysFailEvaluator,
    AlwaysPassEvaluator,
    EvaluationError,
    LLMEvaluator,
    StateEvaluator,
)


def test_state_evaluator():
    gh, scenario = MagicMock(), MagicMock()
    for verdict in (True, False):
        check = MagicMock(return_value=verdict)
        assert StateEvaluator(check).evaluate({}, gh, scenario) is verdict
        check.assert_called_once_with(gh, scenario)


@pytest.mark.parametrize("value", [None, 0, 1, "false", {}])
def test_state_evaluator_rejects_non_boolean(value):
    with pytest.raises(EvaluationError, match="boolean"):
        StateEvaluator(lambda gh, scenario: value).evaluate({}, None, None)


def test_state_evaluator_errors_are_not_negative_verdicts():
    with pytest.raises(EvaluationError, match="API error"):
        StateEvaluator(MagicMock(side_effect=RuntimeError("API error"))).evaluate({}, None, None)


@pytest.mark.parametrize("verdict", [True, False])
def test_llm_evaluator_boolean(verdict):
    response = SimpleNamespace(text=json.dumps({"is_success": verdict, "reasoning": "Evidence"}))
    evaluator = LLMEvaluator(rubric="Did it work?")
    with patch("gitinject.utils.llm.call_llm", return_value=response):
        assert evaluator.evaluate({"agent_output": "Output"}, None, SimpleNamespace(runtime_state={})) is verdict
    assert evaluator.last_result["reasoning"] == "Evidence"


@pytest.mark.parametrize(
    "raw",
    [
        '{"is_success": "false", "reasoning": "No"}',
        '{"is_success": 1, "reasoning": "Yes"}',
        '{"reasoning": "Missing verdict"}',
        "null",
        "{}",
        "not JSON",
        '{"is_success": true, "reasoning": null}',
    ],
)
def test_llm_evaluator_rejects_invalid_verdicts(raw):
    with patch("gitinject.utils.llm.call_llm", return_value=SimpleNamespace(text=raw)):
        with pytest.raises(EvaluationError):
            LLMEvaluator("rubric").evaluate({"agent_output": "Output"}, None, SimpleNamespace(runtime_state={}))


def test_llm_evaluator_api_error():
    with patch("gitinject.utils.llm.call_llm", side_effect=RuntimeError("provider unavailable")):
        with pytest.raises(EvaluationError, match="provider unavailable"):
            LLMEvaluator("rubric").evaluate({"agent_output": "Output"}, None, SimpleNamespace(runtime_state={}))


def test_always_pass_fail():
    assert AlwaysPassEvaluator().evaluate({}, None, None) is True
    assert AlwaysFailEvaluator().evaluate({}, None, None) is False
