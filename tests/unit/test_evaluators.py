import os
from unittest.mock import MagicMock, patch

from src.benchmark.evaluators import AlwaysFailEvaluator, AlwaysPassEvaluator, LLMEvaluator, StateEvaluator


def test_state_evaluator():
    mock_gh = MagicMock()
    mock_scenario = MagicMock()

    # Test success case
    check_func_success = MagicMock(return_value=True)
    evaluator_success = StateEvaluator(check_func_success)
    assert evaluator_success.evaluate({}, mock_gh, mock_scenario) is True
    check_func_success.assert_called_once_with(mock_gh, mock_scenario)

    # Test failure case
    check_func_fail = MagicMock(return_value=False)
    evaluator_fail = StateEvaluator(check_func_fail)
    assert evaluator_fail.evaluate({}, mock_gh, mock_scenario) is False

    # Test exception handling
    check_func_error = MagicMock(side_effect=Exception("API error"))
    evaluator_error = StateEvaluator(check_func_error)
    assert evaluator_error.evaluate({}, mock_gh, mock_scenario) is False


def test_llm_evaluator_success():
    with patch("google.genai.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_response = MagicMock()
        mock_response.parsed = MagicMock(is_success=True, reasoning="The agent succeeded.")
        mock_client.models.generate_content.return_value = mock_response

        with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"}):
            evaluator = LLMEvaluator(rubric="Did it work?")
            assert evaluator.evaluate({"stdout": "I did it"}, MagicMock(), MagicMock()) is True


def test_llm_evaluator_failure():
    with patch("google.genai.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_response = MagicMock()
        mock_response.parsed = MagicMock(is_success=False, reasoning="The agent failed.")
        mock_client.models.generate_content.return_value = mock_response

        with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"}):
            evaluator = LLMEvaluator(rubric="Did it work?")
            assert evaluator.evaluate({"stdout": "I failed"}, MagicMock(), MagicMock()) is False


def test_llm_evaluator_missing_api_key():
    with patch.dict(os.environ, {}, clear=True):
        evaluator = LLMEvaluator(rubric="Did it work?")
        assert evaluator.evaluate({"stdout": "I did it"}, MagicMock(), MagicMock()) is False


def test_always_pass_fail():
    assert AlwaysPassEvaluator().evaluate({}, None, None) is True
    assert AlwaysFailEvaluator().evaluate({}, None, None) is False
