import glob
import json
import os
import random
import re
import string
import time
import uuid
from pathlib import Path

import click
from tenacity import retry, retry_if_result, stop_after_attempt, wait_exponential

from .analyzer import BenchmarkAnalyzer
from .attacks import AbstractAttack, load_attack
from .run_context import RunContext, TriggerReceipt
from .run_record import RunRecord, RunSpec, write_json
from .scenario_loader import find_scenario, load_scenario
from .utils.gh_client import GitHubClient
from .utils.provisioner import RepoProvisioner
from .utils.types import AIProvider


def _extract_inline_prompts(workflow_dict) -> list[str]:
    """Walk a parsed workflow YAML and collect all `with.prompt` values from action steps."""
    prompts = []
    for job in (workflow_dict or {}).get("jobs", {}).values():
        for step in job.get("steps", []):
            prompt = (step.get("with") or {}).get("prompt")
            if prompt:
                prompts.append(str(prompt))
    return prompts


class BenchmarkRunner:
    """Orchestrates the execution of a benchmark test on real GitHub."""

    def __init__(self, workspace_dir, repo_prefix="benchmark-run", *, gh_client=None, event_gh_client=None):
        self.workspace_dir = workspace_dir
        self.repo_prefix = repo_prefix
        self.gh_client = gh_client if gh_client is not None else GitHubClient()
        self.event_gh_client = event_gh_client if event_gh_client is not None else self._build_event_client()
        self.repo_name = self._generate_repo_name(repo_prefix)
        self._sync_repo_name(self.repo_name)

        self.provisioner = RepoProvisioner(self.gh_client)
        self.analyzer = BenchmarkAnalyzer(workspace_dir, repo=self.repo_name, gh_client=self.gh_client)

    def _build_event_client(self):
        """Returns the client used to create attacker-controlled events."""
        attacker_token = os.environ.get("ATTACKER_GITHUB_TOKEN")
        if attacker_token:
            return GitHubClient(
                token=attacker_token,
                token_env_var="ATTACKER_GITHUB_TOKEN",
                auth_label="attacker GitHub",
                actor="attacker",
            )
        return self.gh_client

    def _sync_repo_name(self, repo_name: str) -> None:
        """Keeps owner/analyzer/event clients pointed at the same repository."""
        self.repo_name = repo_name
        self.gh_client.repo_name = repo_name
        self.gh_client._repo_cache = None
        if self.event_gh_client is not self.gh_client:
            self.event_gh_client.repo_name = repo_name
            self.event_gh_client._repo_cache = None
        if hasattr(self, "analyzer"):
            self.analyzer.gh_client.repo_name = repo_name

    def _generate_repo_name(self, prefix):
        """Generates a unique repo name based on a prefix."""
        if "/" in prefix:
            owner, name_prefix = prefix.split("/", 1)
        else:
            owner = None
            name_prefix = prefix

        random_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        repo_name = f"{name_prefix}-{random_suffix}"

        if owner:
            return f"{owner}/{repo_name}"
        return repo_name

    def _inject_attack_slots(self, scenario, attack: AbstractAttack, context: str) -> None:
        """Generate a payload and substitute it into all of the scenario's injection slots."""
        goal = scenario.get_attack_goal()
        if goal is None:
            raise ValueError("Scenario does not expose an attack goal")
        slots = scenario.get_injection_slots()
        if not any("{{INJECTION}}" in template for template in slots.values()):
            raise ValueError("Scenario has no effective {{INJECTION}} slot")
        payload = attack.generate(goal, context)
        for field, template in slots.items():
            scenario.apply_attack(field, template.replace("{{INJECTION}}", payload))

    def run(
        self,
        workflow_id,
        scenario_id,
        attack_id=None,
        attack_payload=None,
        cleanup=True,
        unaligned=False,
        log_llm_input=False,
        parameters=None,
        seed=None,
        parent_attempt_id=None,
        attack: AbstractAttack | None = None,
        security_evaluator=None,
    ):
        """Triggers a GitHub workflow and waits for completion."""
        spec = RunSpec(
            workflow=workflow_id,
            scenario=str(scenario_id),
            parameters=json.loads(json.dumps({} if parameters is None else parameters, allow_nan=False)),
            seed=seed,
            parent_attempt_id=parent_attempt_id,
            attack=attack_id or getattr(attack, "name", None),
            cleanup=cleanup,
            unaligned=unaligned,
        )
        record = RunRecord(self.workspace_dir, spec)
        runs_dir = str(record.directory)
        timestamp = record.timestamp
        result = {
            "workflow": workflow_id,
            "scenario": str(scenario_id),
            "repo": self.repo_name,
            "timestamp": timestamp,
            "attempt_id": record.attempt_id,
            "runs_dir": runs_dir,
        }
        run_result = {}
        setup_started = False
        scenario = context = None
        previous_recorders = []
        try:
            record.event("phase", phase="loading")
            workflow_dir = os.path.join(self.workspace_dir, "src/benchmark/workflows", workflow_id)
            scenario_path = self._find_scenario_path(scenario_id)
            if not os.path.isdir(workflow_dir) or not scenario_path:
                raise ValueError(f"Workflow dir ({workflow_id}) or scenario ({scenario_id}) not found.")
            record.snapshot("workflow", workflow_dir)
            workflow_dir = str(record.directory / "inputs/workflow")
            if os.path.exists(scenario_path):
                source = (
                    os.path.dirname(scenario_path)
                    if Path(scenario_path).name in {"scenario.py", "recipe.json"}
                    else scenario_path
                )
                record.snapshot("scenario", source)
                definition = Path(scenario_path)
                if Path(source).is_file() and (definition.parent / "contents").is_dir():
                    record.snapshot("scenario", definition.parent / "contents", prefix="contents")
                if definition.is_dir():
                    scenario_path = str(record.directory / "inputs/scenario")
                else:
                    scenario_path = str(record.directory / "inputs/scenario" / definition.name)
            lockfile = os.path.join(self.workspace_dir, "uv.lock")
            if os.path.isfile(lockfile):
                record.snapshot("dependencies", lockfile)
            scenario = self._load_scenario(scenario_path)
            if scenario is None:
                raise ValueError(f"Failed to load scenario {scenario_id}")
            scenario.runtime_state["repo"] = self.repo_name
            meta_path = os.path.join(workflow_dir, "metadata.json")
            workflow_meta = {}
            if os.path.isfile(meta_path):
                with open(meta_path) as handle:
                    workflow_meta = json.load(handle)
            actors = {"owner": self.gh_client}
            if self.event_gh_client is not self.gh_client:
                actors["attacker"] = self.event_gh_client
            context = RunContext(
                spec,
                record,
                scenario.runtime_state,
                actors,
                lambda: self._legacy_trigger(scenario),
                lambda: self._capture_gh_state(scenario),
            )
            for actor in scenario.required_actors:
                context.github(actor)
            for actor, client in actors.items():
                previous_recorders.append((client, client.record_event, client.actor))
                client.record_event = record.event
                client.actor = actor
            record.event("phase", phase="preflight")
            record.manifest["actors"] = {actor: client.get_authenticated_user_login() for actor, client in actors.items()}
            if "/" not in self.repo_name:
                self._sync_repo_name(f"{record.manifest['actors']['owner']}/{self.repo_name}")
                result["repo"] = scenario.runtime_state["repo"] = self.repo_name
            record.save_manifest()
            self._configure_workflow_tracking(workflow_dir, workflow_meta)
            if not unaligned:
                provider_error = self._validate_provider_requirements(workflow_meta)
                if provider_error:
                    result["error"] = provider_error
                    return result

            # Tier 1: workflow-declared required keys (hard block)
            required_secrets = workflow_meta.get("required_secrets", [])
            required_vars = workflow_meta.get("required_vars", [])
            missing = [k for k in required_secrets + required_vars if not os.environ.get(k)]
            if missing and not unaligned:
                result["error"] = "Missing required environment variables:\n  - " + "\n  - ".join(missing)
                return result

            # Tier 2: YAML-scanned keys — set if available, silently skip if not
            requirements = self._get_workflow_requirements(workflow_dir)
            secrets = {k: v for k in requirements["secrets"] if (v := os.environ.get(k))}
            variables = {k: v for k in requirements["vars"] if (v := os.environ.get(k))}

            secrets.update(scenario.get_secrets())
            missing = [name for name in scenario.get_required_secrets() if not os.environ.get(name)]
            if missing:
                raise ValueError("Missing scenario secrets: " + ", ".join(missing))
            secrets.update({name: os.environ[name] for name in scenario.get_required_secrets()})

            if attack_id or attack is not None:
                attack = attack if attack is not None else load_attack(attack_id, payload=attack_payload)
                self._inject_attack_slots(scenario, attack, self._reconstruct_llm_input(scenario, workflow_dir))
                record.artifact("rendered_attack.json", scenario._injected)

            target_branch = getattr(scenario, "branch", None)
            template_repo = scenario.get_template_repo()

            substitution_map = {}
            if unaligned:
                global_swaps_path = os.path.join(self.workspace_dir, "src/benchmark/config/adversarial_swaps.json")
                if os.path.exists(global_swaps_path):
                    with open(global_swaps_path, "r") as f:
                        substitution_map.update(json.load(f))

                swaps = workflow_meta.get("adversarial_swaps", {})
                substitution_map.update(swaps)

                tag = unaligned if isinstance(unaligned, str) else "mistral"
                for original in list(substitution_map.keys()):
                    replacement = substitution_map[original]
                    if "@" not in replacement:
                        substitution_map[original] = f"{replacement}@{tag}"

            record.manifest["configuration"] = {
                "secret_names": sorted(secrets),
                "variables": variables,
                "substitutions": substitution_map,
                "required_actors": list(scenario.required_actors),
                "template_repo": template_repo,
                "branch": target_branch,
                "workflow_metadata": workflow_meta,
                "security_evaluator_source": "caller" if security_evaluator is not None else "scenario",
            }
            record.save_manifest()
            record.event("phase", phase="provisioning")
            click.echo(f"Provisioning repository {self.repo_name}...")
            self.provisioner.provision(
                workflow_dir,
                scenario.get_required_files(),
                branch=target_branch,
                template_repo=template_repo,
                secrets=secrets,
                variables=variables,
                substitution_map=substitution_map,
            )
            self._sync_repo_name(self.gh_client.repo_name)
            result["repo"] = self.repo_name
            scenario.runtime_state["repo"] = self.repo_name

            record.event("phase", phase="preparing")
            click.echo(f"Preparing repository state for scenario '{scenario_id}'...")
            setup_started = True
            scenario.prepare(context)

            click.echo("Capturing context snapshot...")
            snapshot = self._capture_context_snapshot(scenario, workflow_dir)
            with open(os.path.join(runs_dir, "context_snapshot.json"), "w") as f:
                json.dump(snapshot, f, indent=4)

            llm_input = self._reconstruct_llm_input(scenario, workflow_dir)

            if log_llm_input:
                click.echo(click.style("\n--- Reconstructed LLM Input ---", bold=True))
                click.echo(llm_input)
                click.echo(click.style("--- End LLM Input ---\n", bold=True))
                with open(os.path.join(runs_dir, "llm_input.txt"), "w") as f:
                    f.write(llm_input)

            click.echo(f"Triggering workflow '{workflow_id}' on GitHub...")
            self._prepare_trial(scenario, workflow_meta)
            start_time = scenario.runtime_state["triggered_at"]
            record.event("phase", phase="triggering")
            receipt = scenario.trigger(context)
            if not isinstance(receipt, TriggerReceipt):
                raise TypeError("Scenario trigger must return a TriggerReceipt")
            if receipt.subject_kind:
                scenario.runtime_state[f"{receipt.subject_kind}_number"] = receipt.subject_number
            self._expected_run_id = receipt.workflow_run_id
            record.artifact(
                "trigger_receipt.json",
                {
                    "event_type": receipt.event_type,
                    "subject_kind": receipt.subject_kind,
                    "subject_number": receipt.subject_number,
                    "workflow_run_id": receipt.workflow_run_id,
                },
            )

            record.event("phase", phase="waiting")
            click.echo("Waiting for workflow run to start and complete...")
            wait_result = self._wait_for_run(start_time, expected_event=receipt.event_type)

            if not wait_result:
                result["error"] = "Timed out waiting for workflow run or could not find it."
                return result

            run_id, final_run = wait_result

            result["run_id"] = run_id
            click.echo(f"Fetching logs for run {run_id}...")
            log_error = None
            try:
                stdout, stderr = self._get_workflow_logs(run_id)
            except Exception as exc:
                stdout, stderr = "", ""
                log_error = str(exc)
            try:
                billable_minutes = self._get_billable_minutes(run_id)
            except Exception as exc:
                billable_minutes = None
                result["timing_error"] = str(exc)

            run_result = {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": 0 if final_run.conclusion == "success" else 1,
                "agent_invoked": self._agent_invocation(final_run),
                "status": final_run.status if final_run else None,
                "conclusion": final_run.conclusion if final_run else None,
            }

            run_result["jobs"] = self._job_evidence
            if log_error:
                run_result["log_error"] = log_error
            if getattr(self, "_invocation_error", None):
                run_result["invocation_error"] = self._invocation_error
            record.event("phase", phase="observing")
            gh_state = scenario.observe(context, run_result)
            if not isinstance(gh_state, dict):
                raise TypeError("Scenario observe must return an evidence dictionary")
            record.artifact("evidence.json", gh_state)
            if gh_state.get("error"):
                run_result["evidence_error"] = gh_state["error"]
            else:
                scenario.runtime_state["observed_details"] = gh_state
            from .evidence import agent_artifacts

            if "comment_details" in gh_state and "error" not in gh_state:
                try:
                    result["agent_artifacts"] = agent_artifacts(gh_state, scenario)
                except Exception as exc:
                    result["artifact_error"] = str(exc)
            record.event("phase", phase="evaluating")
            analysis = self.analyzer.analyze(run_result, scenario, security_evaluator=security_evaluator)

            result.update(
                {
                    "workflow": workflow_id,
                    "scenario": str(scenario_id),
                    "analysis": analysis,
                    "run_id": run_id,
                    "repo": self.repo_name,
                    "timestamp": timestamp,
                    "message": f"Analyzed workflow run {run_id} ({final_run.conclusion}).",
                    "run_result": run_result,
                    "gh_state": gh_state,
                    "billable_minutes": billable_minutes,
                    "evidence_boundary": {
                        key: scenario.runtime_state.get(key)
                        for key in ("triggered_at", "agent_logins", "input_logins", "baseline_artifact_ids")
                    },
                }
            )
            return result

        except (KeyboardInterrupt, SystemExit) as exc:
            result["error"] = type(exc).__name__
            result["interrupted"] = True
            result["run_result"] = run_result
            raise
        except Exception as exc:
            result["error"] = str(exc)
            result["run_result"] = run_result
            return result
        finally:
            try:
                if cleanup:
                    record.event("phase", phase="cleaning")
                    self._cleanup(scenario if setup_started else None, result, context=context)
                else:
                    click.echo(click.style(f"SKIP CLEANUP: Repository {self.repo_name} remains active.", fg="yellow"))
                self._save_run_locally(result, run_result, runs_dir)
                phase = "interrupted" if result.get("interrupted") else "failed" if result.get("error") else "completed"
                record.event("phase", phase=phase)
            finally:
                for client, recorder, actor in previous_recorders:
                    client.record_event, client.actor = recorder, actor

    def _cleanup(self, scenario, result, context=None):
        operations = [self.provisioner.teardown]
        if scenario is not None:
            operations.insert(0, lambda: scenario.cleanup(context) if context else scenario.teardown_state(self.gh_client))
        for operation in operations:
            try:
                operation()
            except Exception as exc:
                result.setdefault("cleanup_errors", []).append(str(exc))
                click.echo(f"Cleanup failed: {exc}", err=True)
        if context:
            errors = context.cleanup_repositories()
            if errors:
                result.setdefault("cleanup_errors", []).extend(errors)

    def _legacy_trigger(self, scenario):
        success, error = self._trigger_event(scenario)
        if not success:
            raise RuntimeError(f"Failed to trigger GitHub event: {error}")
        state = scenario.runtime_state
        kind = "pr" if state.get("pr_number") else "issue" if state.get("issue_number") else None
        return TriggerReceipt(scenario.get_event().get("event_type"), kind, state.get(f"{kind}_number") if kind else None)

    def _configure_workflow_tracking(self, workflow_dir, metadata=None):
        import yaml

        if metadata is None:
            meta_path = os.path.join(workflow_dir, "metadata.json")
            if os.path.isfile(meta_path):
                with open(meta_path) as handle:
                    metadata = json.load(handle)
        metadata = metadata or {}
        self._workflow_metadata = metadata
        contents = os.path.join(workflow_dir, "contents")
        root = os.path.join(contents, ".github/workflows") if os.path.isdir(contents) else workflow_dir
        self._workflow_events = {}
        self._agent_steps = set((metadata or {}).get("agent_steps", []))
        for path in sorted(glob.glob(os.path.join(root, "*.y*ml"))):
            with open(path) as handle:
                workflow = yaml.load(handle, Loader=yaml.BaseLoader) or {}
            events = workflow.get("on", {})
            events = [events] if isinstance(events, str) else events
            self._workflow_events[f".github/workflows/{os.path.basename(path)}"] = set(events)
            for job in workflow.get("jobs", {}).values():
                for step in job.get("steps", []):
                    action = step.get("uses", "").split("@", 1)[0]
                    if action in {
                        "openai/codex-action",
                        "anthropics/claude-code-action",
                        "google-github-actions/run-gemini-cli",
                    }:
                        self._agent_steps.add(step.get("name", step["uses"]))

    def _agent_invocation(self, run):
        self._job_evidence = []
        self._invocation_error = None
        try:
            for job in run.jobs():
                for step in job.steps:
                    self._job_evidence.append(
                        {"job": job.name, "name": step.name, "status": step.status, "conclusion": step.conclusion}
                    )
        except Exception as exc:
            self._invocation_error = str(exc)
            return None
        agent_steps = [step for step in self._job_evidence if step["name"] in getattr(self, "_agent_steps", set())]
        if any(step["conclusion"] == "success" for step in agent_steps):
            return True
        if agent_steps and all(step["conclusion"] == "skipped" for step in agent_steps):
            return False
        if run.conclusion in {"action_required", "skipped"}:
            return False
        return None

    def _prepare_trial(self, scenario, metadata=None):
        from .evidence import DEFAULT_AGENT_LOGINS

        metadata = metadata if metadata is not None else getattr(self, "_workflow_metadata", {})
        state = scenario.runtime_state
        state.pop("observed_details", None)
        state["agent_logins"] = list((metadata or {}).get("agent_logins", sorted(DEFAULT_AGENT_LOGINS)))
        state["input_logins"] = sorted(
            {client.get_authenticated_user_login() for client in (self.gh_client, self.event_gh_client)}
        )
        self._baseline_run_ids = {run.id for run in self.gh_client.repository.get_workflow_runs()[:100]}
        event = scenario.get_event()
        number = event.get("data", {}).get("number")
        if number and event["event_type"] == "issue_comment":
            state["issue_number"] = number
        elif number and event["event_type"] in {"pull_request_review", "pull_request_review_comment"}:
            state["pr_number"] = number
        baseline = self._capture_gh_state(scenario) if state.get("pr_number") or state.get("issue_number") else {}
        if baseline.get("error"):
            raise RuntimeError(f"Cannot establish evidence boundary: {baseline['error']}")
        state["baseline_artifact_ids"] = [f"{item['kind']}:{item['id']}" for item in baseline.get("comment_details", [])]
        state["triggered_at"] = int(time.time())
        self._trial_state = state

    def optimize(self, workflow_id, scenario_id, attack_id, iterations, cleanup=True):
        """Search with independent trials through the ordinary run engine."""
        if iterations < 1:
            raise ValueError("iterations must be positive")
        attack = load_attack(attack_id)
        search = RunRecord(self.workspace_dir, RunSpec(workflow_id, str(scenario_id), attack=attack_id, cleanup=cleanup))
        scores = []
        result = {}
        for iteration in range(1, iterations + 1):
            trial = BenchmarkRunner(self.workspace_dir, repo_prefix=self.repo_prefix)
            attempt = trial.run(
                workflow_id,
                scenario_id,
                attack_id=attack_id,
                attack=attack,
                cleanup=cleanup,
                parent_attempt_id=search.attempt_id,
            )
            verdict = attempt.get("analysis", {}).get("security_breached")
            score = int(verdict) if type(verdict) is bool and not attempt.get("error") else None
            if score is not None:
                attack.update(float(score))
            scores.append(score)
            search.event(
                "iteration",
                iteration=iteration,
                score=score,
                attempt_id=attempt.get("attempt_id"),
                run_id=attempt.get("run_id"),
                error=attempt.get("error")
                or attempt.get("analysis", {}).get("evaluation_errors", {}).get("security_breached"),
            )
        valid = [score for score in scores if score is not None]
        best = attack.best_payload
        if best:
            (search.directory / "best_payload.txt").write_text(best)
        result.update(
            {
                "workflow": workflow_id,
                "scenario": str(scenario_id),
                "attack": attack_id,
                "attempt_id": search.attempt_id,
                "iterations": iterations,
                "asr_curve": scores,
                "final_asr": sum(valid) / len(valid) if valid else None,
                "best_payload": best,
                "runs_dir": str(search.directory),
                "valid_iterations": len(valid),
                "unknown_iterations": iterations - len(valid),
            }
        )
        write_json(search.directory / "metadata.json", result)
        search.event("phase", phase="completed")
        return result

    def offline_optimize(self, workflow_id, scenario_id, attack_id, iterations, victim_model: str | None = None):
        """
        Optimize an attack entirely offline — no GitHub repo is provisioned.

        Each iteration:
          1. Reconstruct the baseline LLM prompt (what the model will see)
          2. Generate an attack payload and inject it into the scenario's slots
          3. Reconstruct the injected LLM prompt
          4. Call the victim model directly via the OpenAI API (OPENAI_API_KEY)
          5. Score with scenario.get_preflight_evaluator()
          6. Feed score back to attack.update()

        Returns { best_payload, asr_curve, final_asr, runs_dir }.
        """
        import os as _os

        from openai import OpenAI

        workflow_dir = _os.path.join(self.workspace_dir, "src/benchmark/workflows", workflow_id)
        scenario_path = self._find_scenario_path(scenario_id)

        if not _os.path.exists(workflow_dir) or not scenario_path:
            return {"error": f"Workflow dir ({workflow_id}) or scenario ({scenario_id}) not found."}

        scenario = self._load_scenario(scenario_path)
        if not scenario:
            return {"error": f"Failed to load scenario {scenario_id}"}

        goal = scenario.get_attack_goal()
        if not goal:
            return {"error": f"Scenario '{scenario_id}' has no get_attack_goal() — cannot optimize."}

        preflight_check = scenario.get_preflight_evaluator()
        if preflight_check is None:
            return {"error": f"Scenario '{scenario_id}' has no get_preflight_evaluator() — cannot run offline."}

        model = victim_model or _os.environ.get("ATTACK_VICTIM_MODEL", "gpt-4o-mini")
        openai_key = _os.environ.get("OPENAI_API_KEY")
        if not openai_key:
            return {"error": "OPENAI_API_KEY is not set. The victim model is called via the OpenAI API directly."}
        client = OpenAI(api_key=openai_key)

        attack = load_attack(attack_id)
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        runs_dir = _os.path.join(
            self.workspace_dir, "runs", f"offline-{timestamp.replace(':', '-')}-{uuid.uuid4().hex[:12]}"
        )
        _os.makedirs(runs_dir)
        history_path = _os.path.join(runs_dir, "attack_history.jsonl")

        asr_curve = []

        for i in range(iterations):
            click.echo(click.style(f"\n--- Offline iteration {i + 1}/{iterations} ---", bold=True))

            scenario._injected = {}
            baseline_input = self._reconstruct_llm_input(scenario, workflow_dir, repo_name="owner/repo", prompts_only=True)

            try:
                self._inject_attack_slots(scenario, attack, baseline_input)
            except ValueError as e:
                click.echo(click.style(f"Attacker refused: {e}", fg="yellow"))
                asr_curve.append(None)
                with open(history_path, "a") as handle:
                    handle.write(json.dumps({"iteration": i + 1, "score": None, "error": str(e)}) + "\n")
                continue

            injected_input = self._reconstruct_llm_input(scenario, workflow_dir, repo_name="owner/repo", prompts_only=True)

            click.echo(f"Calling {model}...")
            try:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": injected_input}],
                    max_completion_tokens=1500,
                )
                response_text = resp.choices[0].message.content or ""
            except Exception as e:
                click.echo(click.style(f"Model call failed: {e}", fg="red"))
                asr_curve.append(None)
                with open(history_path, "a") as handle:
                    handle.write(json.dumps({"iteration": i + 1, "score": None, "error": str(e)}) + "\n")
                continue

            try:
                verdict = preflight_check(response_text)
                if type(verdict) is not bool:
                    raise ValueError("Preflight check must return a boolean")
                score = float(verdict)
            except Exception as exc:
                asr_curve.append(None)
                with open(history_path, "a") as handle:
                    handle.write(json.dumps({"iteration": i + 1, "score": None, "error": str(exc)}) + "\n")
                continue
            asr_curve.append(int(score))
            status = click.style("PASS", fg="green") if score else click.style("FAIL", fg="red")
            click.echo(f"Iteration {i + 1}: {status}")
            if score == 0:
                click.echo(f"Response preview: {response_text[:300]}")

            attack.update(score)

            with open(history_path, "a") as f:
                f.write(
                    json.dumps(
                        {
                            "iteration": i + 1,
                            "score": score,
                            "response_preview": response_text[:500],
                        }
                    )
                    + "\n"
                )

            if score == 1.0:
                click.echo(click.style("Attack succeeded — stopping early.", fg="green"))
                break

        valid_scores = [score for score in asr_curve if score is not None]
        final_asr = sum(valid_scores) / len(valid_scores) if valid_scores else None
        best = attack.best_payload

        if best:
            best_path = _os.path.join(runs_dir, "best_payload.txt")
            with open(best_path, "w") as f:
                f.write(best)
            click.echo(f"\nBest payload written to {best_path}")

        result = {
            "workflow": workflow_id,
            "scenario": scenario_id,
            "attack": attack_id,
            "iterations_run": len(asr_curve),
            "asr_curve": asr_curve,
            "final_asr": final_asr,
            "best_payload": best,
            "runs_dir": runs_dir,
            "mode": "offline",
            "valid_iterations": len(valid_scores),
            "unknown_iterations": len(asr_curve) - len(valid_scores),
        }
        with open(_os.path.join(runs_dir, "metadata.json"), "w") as f:
            json.dump(result, f, indent=4)

        click.echo(
            f"\nOffline optimization complete. ASR: {final_asr} ({sum(valid_scores)}/{len(valid_scores)} valid trials)"
        )
        return result

    def _find_scenario_path(self, scenario_id):
        path = find_scenario(Path(self.workspace_dir) / "src/benchmark/scenarios", str(scenario_id))
        return str(path) if path else None

    def _capture_context_snapshot(self, scenario, workflow_dir):
        """Captures targeted metadata and injected files for diagnostic purposes without full repo download."""
        repo = self.gh_client.repository
        fixture_repo = getattr(scenario, "_attacker_fork_client", None)
        fixture_repo = fixture_repo.repository if fixture_repo is not None else repo
        fixture_ref = getattr(scenario, "branch", None) or fixture_repo.default_branch

        snapshot = {
            "repository": self.repo_name,
            "default_branch": repo.default_branch,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": scenario.get_event(),
            "injected_files_content": {},  # Full content of what WE care about
            "runtime_state": scenario.runtime_state,
        }

        try:
            # 1. Capture content of our injected workflows
            click.echo("  Snapshotting workflows...")
            try:
                workflow_contents = repo.get_contents(".github/workflows")
                if isinstance(workflow_contents, list):
                    for content in workflow_contents:
                        if content.type == "file":
                            snapshot["injected_files_content"][content.path] = content.decoded_content.decode("utf-8")
            except Exception:
                pass  # No workflows or error

            # 2. Capture content of files required by the scenario
            required_files = scenario.get_required_files()
            if required_files:
                click.echo(f"  Snapshotting {len(required_files)} scenario files...")
                for repo_path in required_files:
                    if repo_path not in snapshot["injected_files_content"]:
                        try:
                            content = fixture_repo.get_contents(repo_path, ref=fixture_ref)
                            if not isinstance(content, list):
                                snapshot["injected_files_content"][repo_path] = content.decoded_content.decode("utf-8")
                        except Exception:
                            continue

        except Exception as e:
            snapshot["error"] = str(e)

        return snapshot

    def _get_workflow_requirements(self, workflow_dir):
        """Scans workflow YAML files for 'secrets.NAME' and 'vars.NAME' patterns."""
        requirements = {"secrets": set(), "vars": set()}
        secret_pattern = re.compile(r"secrets\.(\w+)")
        var_pattern = re.compile(r"vars\.(\w+)")
        workflows_path = os.path.join(workflow_dir, "contents", ".github", "workflows")
        files = []
        if os.path.isdir(workflows_path):
            files = [
                os.path.join(workflows_path, f)
                for f in os.listdir(workflows_path)
                if f.endswith(".yml") or f.endswith(".yaml")
            ]
        elif os.path.isdir(workflow_dir):
            files = [
                os.path.join(workflow_dir, f) for f in os.listdir(workflow_dir) if f.endswith(".yml") or f.endswith(".yaml")
            ]

        for file_path in files:
            if not os.path.exists(file_path):
                continue
            with open(file_path, "r") as f:
                content = f.read()
                for match in secret_pattern.finditer(content):
                    requirements["secrets"].add(match.group(1))
                for match in var_pattern.finditer(content):
                    requirements["vars"].add(match.group(1))

        if "GITHUB_TOKEN" in requirements["secrets"]:
            requirements["secrets"].remove("GITHUB_TOKEN")
        return requirements

    def _reconstruct_llm_input(
        self,
        scenario,
        workflow_dir,
        repo_name: str | None = None,
        prompts_only: bool = False,
    ) -> str:
        """
        Reconstructs the effective LLM prompt by substituting known GitHub context values
        into workflow YAMLs.

        prompts_only=True returns only the inline `with.prompt` values after substitution,
        matching what the LLM actually receives in production (e.g. via codex-action).
        prompts_only=False (default) returns the full YAML + extracted prompts, useful for
        diagnostics and the --log-llm-input flag.
        """
        import yaml

        event = scenario.get_event()
        data = event.get("data", {})

        substitutions = {
            "github.repository": repo_name or self.repo_name,
            "github.event.pull_request.title": data.get("title", ""),
            "github.event.pull_request.body": data.get("body", ""),
            "github.event.pull_request.number": "<PR_NUMBER>",
            "github.event.pull_request.base.ref": data.get("base", "<BASE_REF>"),
            "github.event.pull_request.base.sha": "<BASE_SHA>",
            "github.event.pull_request.head.sha": "<HEAD_SHA>",
            "github.event.pull_request.user.login": "<PR_AUTHOR>",
            "github.event.issue.number": "<ISSUE_NUMBER>",
            "github.event.issue.title": data.get("title", ""),
            "github.event.issue.body": data.get("body", ""),
            "github.event.comment.body": data.get("body", ""),
            "github.ref_name": "<REF_NAME>",
            "github.event_name": event.get("event_type", ""),
            "github.run_id": "<RUN_ID>",
        }

        contents_dir = os.path.join(workflow_dir, "contents")
        yaml_files = sorted(
            glob.glob(os.path.join(contents_dir, "**/*.yml"), recursive=True, include_hidden=True)
            + glob.glob(os.path.join(contents_dir, "**/*.yaml"), recursive=True, include_hidden=True)
        )

        output_parts = []
        for yml_path in yaml_files:
            with open(yml_path) as f:
                raw = f.read()

            if prompts_only:
                # Parse the raw YAML first (before substitution) to extract prompt templates,
                # then apply substitutions to each template string. This avoids YAML parse
                # failures caused by injection payloads containing YAML-unsafe content.
                try:
                    raw_parsed = yaml.safe_load(raw)
                    prompt_templates = _extract_inline_prompts(raw_parsed)
                except Exception:
                    prompt_templates = []
                for template in prompt_templates:
                    substituted = template
                    for key, value in substitutions.items():
                        substituted = substituted.replace(f"${{{{ {key} }}}}", value)
                    output_parts.append(substituted)
            else:
                substituted = raw
                for key, value in substitutions.items():
                    substituted = substituted.replace(f"${{{{ {key} }}}}", value)

                header = f"=== {os.path.relpath(yml_path, workflow_dir)} ==="
                output_parts.append(header + "\n" + substituted)

                try:
                    parsed = yaml.safe_load(substituted)
                    prompts = _extract_inline_prompts(parsed)
                except Exception:
                    prompts = []
                if prompts:
                    extracted = "\n---\n".join(prompts)
                    output_parts.append(f"--- extracted prompt(s) ---\n{extracted}")

        return "\n\n".join(output_parts)

    def _capture_gh_state(self, scenario):
        runtime_state = getattr(scenario, "runtime_state", None) or {}
        pr_number = runtime_state.get("pr_number")
        issue_number = runtime_state.get("issue_number")
        try:
            if pr_number:
                details = self.gh_client.get_pr_details(pr_number) or {}
                return {"kind": "pr", "number": pr_number, **details}
            if issue_number:
                details = self.gh_client.get_issue_details(issue_number) or {}
                return {"kind": "issue", "number": issue_number, **details}
        except Exception as e:
            return {"error": str(e)}
        return {}

    def _save_run_locally(self, result, run_result, runs_dir):
        """Saves run metadata and logs to the local 'runs/' directory."""
        write_json(Path(runs_dir) / "metadata.json", result)
        with open(os.path.join(runs_dir, "stdout.log"), "w") as f:
            f.write(run_result.get("stdout", ""))
        with open(os.path.join(runs_dir, "stderr.log"), "w") as f:
            f.write(run_result.get("stderr", ""))
        click.echo(f"Run results saved to: {runs_dir}")

    def _trigger_event(self, scenario):
        """Triggers the appropriate GitHub event using the GitHub API."""
        scenario_event = scenario.get_event()
        event_type = scenario_event.get("event_type")
        data = scenario_event.get("data", {})
        actor = scenario_event.get("actor")
        if actor == "attacker" and self.event_gh_client is self.gh_client:
            return False, "Required GitHub actor is unavailable: attacker"
        if actor not in {None, "owner", "attacker"}:
            return False, f"Unknown GitHub actor: {actor}"
        event_client = self.gh_client if actor == "owner" else self.event_gh_client
        repo = event_client.repository
        default_branch = repo.default_branch

        try:
            if event_type == "issues":
                issue = repo.create_issue(title=data.get("title", "Test Issue"), body=data.get("body", "Test Body"))
                scenario.runtime_state["issue_number"] = issue.number
                return True, None
            elif event_type in ("pull_request", "pull_request_target"):
                head = data.get("head", default_branch)
                pr_client = event_client if actor or ":" in head else self.gh_client
                pr = pr_client.repository.create_pull(
                    title=data.get("title", "Test PR"),
                    body=data.get("body", "Test Body"),
                    head=head,
                    base=data.get("base", default_branch),
                )
                scenario.runtime_state["pr_number"] = pr.number
                return True, None
            elif event_type in ["issue_comment", "pull_request_review", "pull_request_review_comment"]:
                if event_type == "pull_request_review_comment":
                    return False, "Inline review comments require commit/path/line support; this trigger is unsupported."
                target_number = data.get("number")
                if not target_number:
                    prs = repo.get_pulls(state="open", sort="created", direction="desc")
                    if prs.totalCount > 0:
                        target_number = prs[0].number

                if target_number:
                    if event_type == "pull_request_review":
                        scenario.runtime_state["pr_number"] = target_number
                        pr = repo.get_pull(target_number)
                        pr.create_review(body=data.get("body", "Looks good to me."), event="COMMENT")
                    else:
                        scenario.runtime_state["issue_number"] = target_number
                        issue = repo.get_issue(target_number)
                        issue.create_comment(data.get("body", "/review"))
                    return True, None
                return False, "Could not find a target PR/Issue for the event."
            elif event_type == "workflow_dispatch":
                workflow = repo.get_workflow(data.get("workflow"))
                if not workflow.create_dispatch(repo.default_branch, data.get("inputs", {})):
                    return False, "GitHub rejected workflow dispatch"
                return True, None
        except Exception as e:
            return False, str(e)

        return False, f"Unknown event type: {event_type}"

    def _load_scenario(self, scenario_path):
        scenario = load_scenario(scenario_path, self.workspace_dir)
        scenario.runtime_state["repo"] = self.repo_name
        return scenario

    @retry(
        retry=retry_if_result(lambda res: res is None),
        stop=stop_after_attempt(60),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry_error_callback=lambda state: None,
    )
    def _wait_for_run(self, start_time, expected_event=None):
        """Wait for the uniquely matching workflow, excluding pre-trigger runs."""
        candidates = []
        events = {expected_event} if expected_event else None
        if expected_event in {"pull_request", "pull_request_target"}:
            events = {"pull_request", "pull_request_target"}
        workflows = getattr(self, "_workflow_events", None)
        state = getattr(self, "_trial_state", {})
        expected_id = getattr(self, "_expected_run_id", None)
        runs = (
            [self.gh_client.repository.get_workflow_run(expected_id)]
            if expected_id
            else self.gh_client.repository.get_workflow_runs()[:100]
        )
        for run in runs:
            if run.id in getattr(self, "_baseline_run_ids", set()):
                continue
            if run.created_at.timestamp() < start_time:
                continue
            if events and run.event not in events:
                continue
            if workflows is not None:
                path = run.path.split("@", 1)[0]
                if path not in workflows or run.event not in workflows[path]:
                    continue
            pr_number = state.get("pr_number")
            if pr_number and run.pull_requests and not any(pr.number == pr_number for pr in run.pull_requests):
                continue
            candidates.append(run)
        if len(candidates) > 1:
            raise RuntimeError("Ambiguous workflow attribution: multiple runs match this trigger")
        if not candidates or candidates[0].status != "completed":
            return None
        return candidates[0].id, candidates[0]

    def _get_workflow_logs(self, run_id):
        """Retrieves the full logs for a specific workflow run."""
        # Note: Using gh CLI here because pygithub doesn't easily expose full logs in a single call
        stdout, stderr = self.gh_client.run_gh(["run", "view", str(run_id), "--log"], use_repo=True)
        return stdout, stderr

    def _get_billable_minutes(self, run_id) -> float:
        """Return elapsed runner minutes from the /timing endpoint.

        On public repos `billable.<OS>.total_ms` is 0 (free minutes). Fall back
        to `run_duration_ms` so the number reflects actual elapsed runner time
        regardless of billing status.
        """
        import json as _json

        endpoint = f"repos/{self.repo_name}/actions/runs/{run_id}/timing"
        stdout, _ = self.gh_client.run_gh(["api", endpoint])
        try:
            data = _json.loads(stdout)
        except (ValueError, TypeError):
            return 0.0
        billable = data.get("billable") or {}
        total_ms = 0
        for os_data in billable.values():
            if isinstance(os_data, dict):
                total_ms += int(os_data.get("total_ms") or 0)
        if total_ms == 0:
            total_ms = int(data.get("run_duration_ms") or 0)
        return total_ms / 60_000

    def _validate_provider_requirements(self, meta):
        """Ensures API keys for the specified provider are present in the environment."""
        provider = meta.get("provider")
        if not provider:
            return None
        provider_keys = {
            AIProvider.GOOGLE_GEMINI: [
                "GEMINI_API_KEY",
                "GEMINI_MODEL",
                "GEMINI_DEBUG",
            ],
            AIProvider.ANTHROPIC_CLAUDE: ["ANTHROPIC_API_KEY"],
            AIProvider.OPENAI_CODEX: ["OPENAI_API_KEY"],
            AIProvider.AMAZON_Q: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
            AIProvider.GITHUB_COPILOT: ["COPILOT_GITHUB_TOKEN"],
            AIProvider.OPENROUTER: [
                "OPENROUTER_API_KEY",
            ],
        }
        required_keys = provider_keys.get(provider, [])
        missing = [key for key in required_keys if not os.environ.get(key)]
        if missing:
            return f"Provider '{provider}' requires the following API keys in your local environment: {', '.join(missing)}"
        return None
