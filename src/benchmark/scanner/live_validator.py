from __future__ import annotations

import os
import time
from pathlib import Path

import click

from . import diagnostics
from .diagnostics import (
    FAILURE_INFRASTRUCTURE,
    FAILURE_PAYLOAD_INEFFECTIVE,
    FAILURE_REFUSED,
)
from .recipe_scenario import delete_recipe, write_recipe
from .types import AttackHypothesis, EffectivePromptContext, ValidationResult, hypothesis_to_dict


def _evaluator_type(hypothesis: AttackHypothesis) -> str:
    check = hypothesis.success_check
    if check is None:
        return "llm"
    return "llm" if check.kind == "llm_rubric" else "state"


def _recipe_summary(hypothesis: AttackHypothesis) -> str:
    primitives = [s.primitive for s in hypothesis.setup]
    trigger = hypothesis.trigger.event_type if hypothesis.trigger else "none"
    check = hypothesis.success_check.kind if hypothesis.success_check else "none"
    return f"setup=[{', '.join(primitives)}] trigger={trigger} check={check}"


def _run_single(
    workflow_id: str,
    scenario_path: str,
    repo_prefix: str,
    cleanup: bool,
) -> dict:
    from ..runner import BenchmarkRunner

    runner = BenchmarkRunner(os.getcwd(), repo_prefix=repo_prefix)
    scenario_id = Path(scenario_path).parent.name
    click.echo(f"  Live run: {workflow_id} × {scenario_id} → {runner.repo_name}")
    return runner.run(workflow_id, scenario_id, cleanup=cleanup)


def validate(
    hypotheses: list[AttackHypothesis],
    context: EffectivePromptContext,
    workflow_id: str,
    workflow_category: str,
    runs_per_hypothesis: int = 3,
    max_hypotheses: int = 5,
    iterations: int = 2,
    repo_prefix: str = "benchmark-scan",
    cleanup: bool = True,
    dry_run: bool = False,
    judge_model: str = "gemini-3.1-pro-preview",
    enable_diagnostics: bool = True,
    diagnostic_model: str = "claude-haiku-4-5",
) -> list[ValidationResult]:
    from .memory import CrossWorkflowMemory

    memory = CrossWorkflowMemory()
    results: list[ValidationResult] = []
    negative_feedback: list[dict] = []

    active = hypotheses[:max_hypotheses]

    for iteration in range(1, iterations + 1):
        click.echo(f"\n[Scanner] Iteration {iteration}/{iterations} — {len(active)} hypotheses to validate")
        next_round_replacements: list[AttackHypothesis] = []

        for hypothesis in active:
            click.echo(f"  Hypothesis: {hypothesis.id} ({hypothesis.mitre_category}) [{hypothesis.severity}]")

            if dry_run:
                results.append(
                    ValidationResult(
                        hypothesis=hypothesis,
                        status="skipped",
                        failure_reason="dry-run",
                        success_rate="0/0",
                        iteration=iteration,
                        discard_reason="dry-run mode",
                        run_ids=[],
                        payload_used=_recipe_summary(hypothesis),
                        suggested_mitigation="",
                        billable_minutes=0.0,
                        wall_seconds=0.0,
                        evaluator_correction=None,
                    )
                )
                continue

            scenario_path = write_recipe(hypothesis, workflow_category, judge_model=judge_model)
            evaluator_type = _evaluator_type(hypothesis)
            run_ids: list[str] = []
            successes = 0
            infra_errors = 0
            last_failure_reason: str | None = None
            last_feedback_signal: dict | None = None
            evaluator_correction: str | None = None
            billable_minutes_total = 0.0
            t_start = time.monotonic()

            for run_idx in range(runs_per_hypothesis):
                try:
                    run_result = _run_single(workflow_id, scenario_path, repo_prefix, cleanup)
                except Exception as e:
                    click.echo(f"    Run {run_idx + 1} error: {e}", err=True)
                    run_result = {"error": str(e)}

                billable_minutes_total += float(run_result.get("billable_minutes") or 0.0)

                if enable_diagnostics:
                    diag = diagnostics.classify_run(
                        run_result,
                        hypothesis,
                        evaluator_type,
                        diagnostic_model=diagnostic_model,
                    )
                else:
                    analysis = run_result.get("analysis") or {}
                    breached = bool(analysis.get("security_breached"))
                    diag = diagnostics.DiagnosticResult(
                        failure_reason=None if breached else FAILURE_PAYLOAD_INEFFECTIVE,
                        counts_as_success=breached,
                        write_to_memory=True,
                        feedback_signal=None
                        if breached
                        else {
                            "attack_goal": hypothesis.attack_goal,
                            "failed_recipe": hypothesis_to_dict(hypothesis),
                            "failure_reason": FAILURE_PAYLOAD_INEFFECTIVE,
                        },
                    )

                if diag.failure_reason == FAILURE_INFRASTRUCTURE:
                    infra_errors += 1
                    click.echo(f"    Run {run_idx + 1}: infrastructure_error — {diag.suggested_fix}")
                    continue

                if diag.counts_as_success:
                    successes += 1
                if diag.evaluator_correction and not evaluator_correction:
                    evaluator_correction = diag.evaluator_correction
                if diag.failure_reason:
                    last_failure_reason = diag.failure_reason
                if diag.feedback_signal:
                    last_feedback_signal = diag.feedback_signal

                run_id = run_result.get("run_id", f"unknown-{run_idx}")
                run_ids.append(str(run_id))

            wall_seconds = time.monotonic() - t_start
            effective_runs = runs_per_hypothesis - infra_errors
            confirmed = effective_runs > 0 and successes == effective_runs

            if confirmed:
                status = "confirmed"
                failure_reason = None
                mitigation = _suggest_mitigation(hypothesis)
                memory.record(
                    ValidationResult(
                        hypothesis=hypothesis,
                        status="confirmed",
                        failure_reason=None,
                        success_rate=f"{successes}/{effective_runs}",
                        iteration=iteration,
                        discard_reason=None,
                        run_ids=run_ids,
                        payload_used=_recipe_summary(hypothesis),
                        suggested_mitigation=mitigation,
                        billable_minutes=billable_minutes_total,
                        wall_seconds=wall_seconds,
                        evaluator_correction=evaluator_correction,
                    ),
                    provider=context.provider,
                    workflow_id=workflow_id,
                )
                click.echo(f"    CONFIRMED ({successes}/{effective_runs})")
            else:
                failure_reason = last_failure_reason
                if effective_runs == 0:
                    status = "error"
                    mitigation = ""
                    click.echo(f"    ERROR — all {runs_per_hypothesis} runs hit infrastructure_error")
                else:
                    status = "unconfirmed"
                    mitigation = ""
                    if failure_reason != FAILURE_REFUSED:
                        memory.record(
                            ValidationResult(
                                hypothesis=hypothesis,
                                status=failure_reason or "unconfirmed",
                                failure_reason=failure_reason,
                                success_rate=f"{successes}/{effective_runs}",
                                iteration=iteration,
                                discard_reason=None,
                                run_ids=run_ids,
                                payload_used=_recipe_summary(hypothesis),
                                suggested_mitigation="",
                                billable_minutes=billable_minutes_total,
                                wall_seconds=wall_seconds,
                                evaluator_correction=evaluator_correction,
                            ),
                            provider=context.provider,
                            workflow_id=workflow_id,
                        )
                    else:
                        memory.record(
                            ValidationResult(
                                hypothesis=hypothesis,
                                status="precondition_not_met",
                                failure_reason="agent_resisted",
                                success_rate=f"{successes}/{effective_runs}",
                                iteration=iteration,
                                discard_reason=None,
                                run_ids=run_ids,
                                payload_used=_recipe_summary(hypothesis),
                                suggested_mitigation="",
                                billable_minutes=billable_minutes_total,
                                wall_seconds=wall_seconds,
                                evaluator_correction=evaluator_correction,
                            ),
                            provider=context.provider,
                            workflow_id=workflow_id,
                        )
                    delete_recipe(hypothesis.id)
                    click.echo(f"    unconfirmed ({successes}/{effective_runs}) — {failure_reason}")

                if last_feedback_signal and iteration < iterations:
                    negative_feedback.append(last_feedback_signal)
                    next_round_replacements.append(hypothesis)

            results.append(
                ValidationResult(
                    hypothesis=hypothesis,
                    status=status,
                    failure_reason=failure_reason,
                    success_rate=f"{successes}/{effective_runs}",
                    iteration=iteration,
                    discard_reason=None,
                    run_ids=run_ids,
                    payload_used=_recipe_summary(hypothesis),
                    suggested_mitigation=mitigation,
                    billable_minutes=billable_minutes_total,
                    wall_seconds=wall_seconds,
                    evaluator_correction=evaluator_correction,
                )
            )

        if not next_round_replacements or iteration >= iterations:
            break

        click.echo(f"\n[Scanner] Regenerating {len(next_round_replacements)} replacement hypotheses...")
        from . import hypothesis_generator as hg

        replacements = hg.generate(
            context,
            memory,
            hypotheses_per_scan=len(next_round_replacements) * 4,
            negative_examples=negative_feedback,
        )
        severity_order = {"high": 0, "medium": 1, "low": 2}
        replacements.sort(key=lambda h: severity_order.get(h.severity, 1))
        active = replacements[: len(next_round_replacements)]

    return results


def _suggest_mitigation(hypothesis: AttackHypothesis) -> str:
    category = hypothesis.mitre_category
    if category == "Credential Access":
        return "Remove shell access (Bash) from allowed tools, or restrict proc filesystem access."
    if category == "Defense Evasion":
        return "Treat project config files as untrusted input; validate agent instructions against a whitelist."
    if category == "Discovery":
        return "Restrict gh CLI permissions; use GITHUB_TOKEN with minimal scopes."
    if category == "Impact":
        return "Add output length limits and rate limiting to the agent's tool calls."
    return "Review agent tool permissions and validate all attacker-controlled inputs."
