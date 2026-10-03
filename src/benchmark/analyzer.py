from .scenario_base import AbstractScenario
from .utils.gh_client import GitHubClient


class BenchmarkAnalyzer:
    """Evaluates the results of a benchmark run for Utility and Security."""

    def __init__(self, workspace_dir, repo="owner/repo", gh_client=None):
        self.workspace_dir = workspace_dir
        self.gh_client = gh_client if gh_client is not None else GitHubClient(repo)

    def analyze(self, run_result, scenario_obj):
        """
        Analyzes a run result and returns Utility, Security and Autonomy results.
        """
        errors = {}
        evaluations = {}
        verdicts = {}
        for metric, factory in (
            ("utility_achieved", "get_utility_evaluator"),
            ("security_breached", "get_security_evaluator"),
        ):
            evaluator = None
            try:
                if not isinstance(scenario_obj, AbstractScenario):
                    raise ValueError("A declared scenario evaluator is required")
                if run_result.get("evidence_error"):
                    raise ValueError(run_result["evidence_error"])
                evaluator = getattr(scenario_obj, factory)()
                verdict = evaluator.evaluate(run_result, self.gh_client, scenario_obj)
                if type(verdict) is not bool:
                    raise ValueError("Evaluator must return a boolean")
                if verdict is False and run_result.get("agent_invoked") is not True:
                    raise ValueError("No verified agent invocation; negative verdict is unknown")
                if metric == "utility_achieved" and run_result.get("agent_invoked") is not True:
                    raise ValueError("No verified agent invocation; utility is unknown")
                verdicts[metric] = verdict
                evaluations[metric] = getattr(evaluator, "last_result", None)
            except Exception as exc:
                verdicts[metric] = None
                errors[metric] = str(exc)
                evaluations[metric] = getattr(evaluator, "last_result", None)
        status = run_result.get("status")
        conclusion = run_result.get("conclusion")

        autonomy_achieved = run_result.get("agent_invoked")
        utility_achieved = verdicts["utility_achieved"]
        security_breached = verdicts["security_breached"]

        return {
            "utility_achieved": utility_achieved,
            "security_breached": security_breached,
            "autonomy_achieved": autonomy_achieved,
            "evaluation_errors": errors,
            "details": {
                "utility_achieved": utility_achieved,
                "security_breached": security_breached,
                "autonomy_achieved": autonomy_achieved,
                "status": status,
                "conclusion": conclusion,
                "evaluations": evaluations,
            },
        }
