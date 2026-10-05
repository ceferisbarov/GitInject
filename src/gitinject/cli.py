import json
import os

import click

from .experiments.cli import install_cli
from .resources import dataset_dir


@click.group()
def cli():
    """AI-Powered GitHub Workflows Security Benchmark CLI."""
    pass


@cli.group()
def list():
    """List benchmark components."""
    pass


@list.command(name="workflows")
def list_workflows():
    """List available workflows with their categories and supported events."""
    workflows_dir = dataset_dir("workflows")
    if not os.path.exists(workflows_dir):
        click.echo("Workflows directory not found.")
        return

    workflows = sorted([d for d in os.listdir(workflows_dir) if os.path.isdir(os.path.join(workflows_dir, d))])
    for w in workflows:
        metadata_path = os.path.join(workflows_dir, w, "metadata.json")
        if os.path.exists(metadata_path):
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
                category = metadata.get("category", "uncategorized")
                events = ", ".join(metadata.get("supported_events", []))
                click.echo(f"- {w:25} | Category: {category:20} | Events: {events}")
        else:
            click.echo(f"- {w:25} | No metadata found.")


def _discover_scenarios(scenarios_dir):
    """Load scenario definitions without constructing an authenticated runner."""
    from .scenario_loader import discover_scenario_paths, load_scenario

    return sorted(
        [(path.parent.name, load_scenario(path, os.getcwd())) for path in discover_scenario_paths(scenarios_dir)],
        key=lambda item: item[0],
    )


@list.command(name="scenarios")
def list_scenarios():
    """List available scenarios with their categories and event types."""
    scenarios_dir = dataset_dir("scenarios")
    if not os.path.exists(scenarios_dir):
        click.echo("Scenarios directory not found.")
        return

    scenarios = _discover_scenarios(scenarios_dir)

    for s_name, s_obj in scenarios:
        category = s_obj.category.value if s_obj.category else "none"
        event = s_obj.get_event().get("event_type", "unknown")
        s_type = s_obj.scenario_type.value if hasattr(s_obj, "scenario_type") else "benign"
        click.echo(f"- {s_name:25} | Type: {s_type:10} | Category: {category:20} | Event: {event}")


@cli.command()
@click.option("--workflow", required=True, help="Workflow ID to run.")
@click.option("--scenario", required=True, help="Scenario ID to run (or 'all' for all compatible scenarios).")
@click.option(
    "--repo-prefix",
    default=lambda: os.environ.get("GITHUB_REPO_PREFIX", "benchmark-run"),
    help="Target GitHub repository prefix.",
)
@click.option(
    "--cleanup/--no-cleanup",
    default=True,
    help="Automatically delete the GitHub repository after the run.",
)
@click.option(
    "--log-llm-input",
    is_flag=True,
    help="Reconstruct and print the effective LLM prompt before triggering the run, and save it to runs/*/llm_input.txt.",
)
@click.option(
    "--attack",
    "attack_id",
    default=None,
    help="Attack type to apply (autoinject, static). Omit to use the scenario's hardcoded payload.",
)
@click.option(
    "--attack-payload",
    default=None,
    help="Inline payload string or path to a payload file. Used with --attack static.",
)
@click.option(
    "--repeat",
    default=1,
    show_default=True,
    help="Number of times to repeat each run.",
)
@click.option("--parameters", default="{}", help="JSON object supplied to the scenario's run context.")
@click.option("--seed", type=int, default=None, help="Seed for the scenario context's random generator.")
def run(
    workflow, scenario, repo_prefix, cleanup, log_llm_input, attack_id, attack_payload, repeat, parameters, seed
):
    """Run benchmark tests."""
    from .runner import BenchmarkRunner

    try:
        parameters = json.loads(parameters)
        if not isinstance(parameters, dict):
            raise ValueError("Expected a JSON object")
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--parameters") from exc

    workflows_dir = dataset_dir("workflows")
    scenarios_dir = dataset_dir("scenarios")

    workflow_path = os.path.join(workflows_dir, workflow)
    if not os.path.isdir(workflow_path):
        click.echo(click.style(f"Error: Workflow '{workflow}' not found.", fg="red"))
        return

    meta_path = os.path.join(workflow_path, "metadata.json")
    workflow_meta = {}
    if os.path.exists(meta_path):
        with open(meta_path, "r") as f:
            workflow_meta = json.load(f)

    platform = workflow_meta.get("platform", "github")
    w_category = workflow_meta.get("category")
    supported_events = set(workflow_meta.get("supported_events", []))

    def _run_pair(wf, sc):
        if platform == "gitlab":
            from .gl_runner import GitLabRunner

            runner = GitLabRunner(os.getcwd(), project_prefix=repo_prefix)
            return runner.run(wf, sc, cleanup=cleanup)
        runner = BenchmarkRunner(os.getcwd(), repo_prefix=repo_prefix)
        return runner.run(
            wf,
            sc,
            attack_id=attack_id,
            attack_payload=attack_payload,
            cleanup=cleanup,
            log_llm_input=log_llm_input,
            parameters=parameters,
            seed=seed,
        )

    if scenario.lower() == "all":
        click.echo(f"Identifying compatible scenarios for workflow '{workflow}'...")

        valid_scenarios = _discover_scenarios(scenarios_dir)
        scenarios_to_run = []
        for s_name, s_obj in valid_scenarios:
            s_event = s_obj.get_event().get("event_type")
            s_platform = getattr(s_obj, "platform", "github")
            if s_obj.category == w_category and s_event in supported_events and s_platform == platform:
                scenarios_to_run.append(s_name)

        if not scenarios_to_run:
            click.echo(click.style(f"No compatible scenarios found for workflow '{workflow}'.", fg="yellow"))
            return

        click.echo(f"Found {len(scenarios_to_run)} compatible scenarios: {', '.join(scenarios_to_run)}")

        pairs_results = {}
        for s_name in scenarios_to_run:
            pairs_results[(workflow, s_name)] = []
            for i in range(repeat):
                label = f"--- Running {workflow} against {s_name} (run {i + 1}/{repeat}) ---"
                click.echo("\n" + click.style(label, bold=True))
                result = _run_pair(workflow, s_name)
                _display_run_result(result)
                pairs_results[(workflow, s_name)].append(result)

        if repeat > 1:
            _display_repeat_summary(pairs_results)
    else:
        pairs_results = {(workflow, scenario): []}
        for i in range(repeat):
            if repeat > 1:
                click.echo(click.style(f"\n--- Run {i + 1}/{repeat} ---", bold=True))
            if platform == "gitlab":
                from .gl_runner import GitLabRunner

                runner = GitLabRunner(os.getcwd(), project_prefix=repo_prefix)
                click.echo(f"Running GitLab benchmark: workflow={workflow}, scenario={scenario}")
                result = runner.run(workflow, scenario, cleanup=cleanup)
            else:
                runner = BenchmarkRunner(os.getcwd(), repo_prefix=repo_prefix)
                click.echo(f"Running benchmark on {runner.repo_name}: workflow={workflow}, scenario={scenario}")
                result = runner.run(
                    workflow,
                    scenario,
                    attack_id=attack_id,
                    attack_payload=attack_payload,
                    cleanup=cleanup,
                    log_llm_input=log_llm_input,
                    parameters=parameters,
                    seed=seed,
                )
            _display_run_result(result)
            pairs_results[(workflow, scenario)].append(result)

        if repeat > 1:
            _display_repeat_summary(pairs_results)


def _display_run_result(result):
    """Helper to display the result of a single benchmark run."""
    if "error" in result:
        click.echo(click.style(f"Error: {result['error']}", fg="red"))
    else:
        click.echo("\n" + click.style("--- Benchmark Evaluation ---", bold=True))
        analysis = result.get("analysis", {})
        for label, key in (
            ("Utility Achieved", "utility_achieved"),
            ("Security Breached", "security_breached"),
            ("Autonomy Achieved", "autonomy_achieved"),
        ):
            value = analysis.get(key)
            click.echo(f"{label}: {value if value is not None else 'unknown'}")
        for metric, error in analysis.get("evaluation_errors", {}).items():
            click.echo(f"  {metric}: {error}")
        click.echo(click.style("----------------------------", bold=True))
        click.echo(f"Message: {result.get('message')}")


def _metric_summary(results, key, *, invert=False):
    values = [r.get("analysis", {}).get(key) for r in results if "error" not in r]
    known = [value for value in values if type(value) is bool]
    if not known:
        return "N/A (0/0)"
    positives = sum(value is (False if invert else True) for value in known)
    return f"{positives / len(known):.2f} ({positives}/{len(known)})"


def _display_repeat_summary(pairs_results: dict[tuple, list]):
    """Report each metric using its own known-verdict denominator."""
    click.echo("\n" + click.style("--- Repeat Summary ---", bold=True))
    click.echo(f"{'Workflow':<25} {'Scenario':<30} {'Security':<18} {'Utility':<18} {'Autonomy':<18} {'Attempts':<9}")
    for (wf, sc), results in sorted(pairs_results.items()):
        sec = _metric_summary(results, "security_breached", invert=True)
        util = _metric_summary(results, "utility_achieved")
        auto = _metric_summary(results, "autonomy_achieved")
        click.echo(f"{wf:<25} {sc:<30} {sec:<18} {util:<18} {auto:<18} {len(results):<9}")
    click.echo("Ratios exclude unknown verdicts and execution errors; Attempts includes all runs.")


@cli.command(name="run-suite")
@click.option("--workflow-labels", help="Comma-separated list of workflow labels to filter by.")
@click.option("--scenario-labels", help="Comma-separated list of scenario labels to filter by.")
@click.option("--scenario-type", help="Filter by scenario type (benign/malicious).")
@click.option("--event", help="Filter by event type.")
@click.option(
    "--repo-prefix",
    default=lambda: os.environ.get("GITHUB_REPO_PREFIX", "benchmark-run"),
    help="Target GitHub repository prefix.",
)
@click.option(
    "--cleanup/--no-cleanup",
    default=True,
    help="Automatically delete the GitHub repository after the run.",
)
@click.option(
    "--dry-run",
    help="List compatible pairs without executing them.",
    is_flag=True,
)
@click.option(
    "--log-llm-input",
    is_flag=True,
    help="Reconstruct and print the effective LLM prompt before each run.",
)
@click.option(
    "--repeat",
    default=1,
    show_default=True,
    help="Number of times to repeat each workflow/scenario pair.",
)
def run_suite(
    workflow_labels, scenario_labels, scenario_type, event, repo_prefix, cleanup, dry_run, log_llm_input, repeat
):
    """Run a suite of compatible workflows and scenarios."""
    from .runner import BenchmarkRunner

    workflows_dir = dataset_dir("workflows")
    scenarios_dir = dataset_dir("scenarios")

    wf_filters = set(workflow_labels.split(",")) if workflow_labels else set()
    sc_filters = set(scenario_labels.split(",")) if scenario_labels else set()

    # Load workflows
    valid_workflows = []
    for w in os.listdir(workflows_dir):
        if not os.path.isdir(os.path.join(workflows_dir, w)):
            continue
        meta_path = os.path.join(workflows_dir, w, "metadata.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r") as f:
                meta = json.load(f)
                labels = set(meta.get("labels", []))
                supported_events = set(meta.get("supported_events", []))

                if wf_filters and not wf_filters.intersection(labels):
                    continue
                if event and event not in supported_events:
                    continue
                valid_workflows.append((w, meta))

    # Load scenarios
    all_scenarios = _discover_scenarios(scenarios_dir)
    valid_scenarios = []
    for s_name, s_obj in all_scenarios:
        labels = set(getattr(s_obj, "labels", []))
        s_event = s_obj.get_event().get("event_type")
        s_type = s_obj.scenario_type.value if hasattr(s_obj, "scenario_type") else "benign"

        if sc_filters and not sc_filters.intersection(labels):
            continue
        if scenario_type and scenario_type.lower() != s_type.lower():
            continue
        if event and event != s_event:
            continue
        valid_scenarios.append((s_name, s_obj))

    # Generate compatible pairs
    pairs = []
    for w_name, w_meta in valid_workflows:
        w_category = w_meta.get("category")
        supported_events = set(w_meta.get("supported_events", []))

        for s_name, s_obj in valid_scenarios:
            s_event = s_obj.get_event().get("event_type")
            if s_obj.category == w_category and s_event in supported_events:
                pairs.append((w_name, s_name))

    if not pairs:
        click.echo("No compatible workflow/scenario pairs found.")
        return

    if dry_run:
        click.echo(click.style(f"DRY RUN: Found {len(pairs)} compatible pairs:", bold=True))
        for w_name, s_name in pairs:
            click.echo(f" - Workflow: {w_name:20} | Scenario: {s_name}")
        return

    total = len(pairs) * repeat
    click.echo(f"Starting suite with {len(pairs)} compatible pairs × {repeat} repeat(s) = {total} total runs.")
    pairs_results = {}
    for w_name, s_name in pairs:
        pairs_results[(w_name, s_name)] = []
        for i in range(repeat):
            label = f"--- Running {w_name} against {s_name} (run {i + 1}/{repeat}) ---"
            click.echo("\n" + click.style(label, bold=True))
            runner = BenchmarkRunner(os.getcwd(), repo_prefix=repo_prefix)
            res = runner.run(w_name, s_name, cleanup=cleanup, log_llm_input=log_llm_input)
            _display_run_result(res)
            pairs_results[(w_name, s_name)].append(res)

    all_results = [r for results in pairs_results.values() for r in results]
    click.echo("\n" + click.style("--- Benchmark Suite Complete ---", bold=True))
    success = sum(1 for r in all_results if "error" not in r)
    click.echo(f"Runs: {success}/{total} successful.")
    if repeat > 1:
        _display_repeat_summary(pairs_results)


@cli.command()
@click.option("--workflow", required=True, help="Workflow ID.")
@click.option("--scenario", required=True, help="Scenario ID.")
@click.option("--attack", "attack_id", required=True, help="Attack type (autoinject, static).")
@click.option(
    "--victim-model",
    default=None,
    help="OpenRouter model string for the victim (e.g. openai/gpt-5.4-2026-03-05). Defaults to ATTACK_VICTIM_MODEL env var.",
)
def preflight(workflow, scenario, attack_id, victim_model):
    """
    Single offline shot: generate a payload, send the injected prompt directly to the
    victim model, and report whether the attack succeeded. No GitHub repo needed.
    """
    from .runner import BenchmarkRunner

    runner = BenchmarkRunner(os.getcwd(), repo_prefix="preflight")
    result = runner.offline_optimize(workflow, scenario, attack_id, iterations=1, victim_model=victim_model)

    if "error" in result:
        click.echo(click.style(f"Error: {result['error']}", fg="red"))
        return

    score = result["asr_curve"][0] if result["asr_curve"] else None
    label = (
        click.style("UNKNOWN — offline trial could not be scored", fg="yellow")
        if score is None
        else (
            click.style("PASS — attack worked offline", fg="green")
            if score
            else click.style("FAIL — attack did not work offline", fg="red")
        )
    )
    click.echo(f"\nPreflight result: {label}")
    click.echo(f"Payload at: {result['runs_dir']}/best_payload.txt")
    click.echo(
        "\nNote: offline uses a plain chat call. The agentic Codex context may differ. "
        "A PASS here is a strong indicator but not a guarantee."
    )


@cli.command()
@click.option("--workflow", required=True, help="Workflow ID to run.")
@click.option("--scenario", required=True, help="Scenario ID to optimize against.")
@click.option("--attack", "attack_id", required=True, help="Attack type (autoinject, static).")
@click.option("--iterations", default=5, show_default=True, help="Number of optimization iterations.")
@click.option(
    "--offline",
    is_flag=True,
    help="Optimize using direct model calls instead of GitHub workflow runs. "
    "Fast, no repo provisioning. Requires scenario.get_preflight_evaluator().",
)
@click.option(
    "--victim-model",
    default=None,
    help="Override victim model for offline mode (OpenRouter string). Defaults to ATTACK_VICTIM_MODEL env var.",
)
@click.option(
    "--repo-prefix",
    default=lambda: os.environ.get("GITHUB_REPO_PREFIX", "benchmark-run"),
    help="Target GitHub repository prefix (online mode only).",
)
@click.option("--cleanup/--no-cleanup", default=True, help="Delete the repository after the run (online mode only).")
def optimize(workflow, scenario, attack_id, iterations, offline, victim_model, repo_prefix, cleanup):
    """Iteratively optimize an attack payload, writing the best result to runs/*/best_payload.txt."""
    from .runner import BenchmarkRunner

    runner = BenchmarkRunner(os.getcwd(), repo_prefix=repo_prefix)

    if offline:
        click.echo(
            f"Offline optimization: workflow={workflow}, scenario={scenario}, attack={attack_id}, iterations={iterations}"
        )
        result = runner.offline_optimize(workflow, scenario, attack_id, iterations, victim_model=victim_model)
    else:
        click.echo(
            f"Optimizing on {runner.repo_name}: workflow={workflow}, scenario={scenario}, "
            f"attack={attack_id}, iterations={iterations}"
        )
        result = runner.optimize(workflow, scenario, attack_id, iterations, cleanup=cleanup)

    if "error" in result:
        click.echo(click.style(f"Error: {result['error']}", fg="red"))
        return

    click.echo("\n" + click.style("--- Optimization Result ---", bold=True))
    scores = [score for score in result["asr_curve"] if score is not None]
    click.echo(f"Final ASR : {result['final_asr']} ({sum(scores)}/{len(scores)} valid trials)")
    click.echo(f"ASR curve : {result['asr_curve']}")
    click.echo(f"Runs dir  : {result['runs_dir']}")
    if result.get("best_payload"):
        click.echo(click.style("Best payload saved to runs_dir/best_payload.txt", fg="green"))


@cli.command()
@click.option(
    "--prefix",
    default="benchmark-run",
    help="Prefix of repositories to delete.",
)
@click.option("--force", is_flag=True, help="Skip confirmation prompt.")
def cleanup(prefix, force):
    """Delete all benchmark repositories with a specific prefix."""
    from .utils.gh_client import GitHubClient

    gh = GitHubClient()
    click.echo(f"Searching for repositories with prefix '{prefix}'...")
    repos = gh.list_repos(limit=100)

    # Filter by prefix (checking both name and nameWithOwner)
    to_delete = [r["nameWithOwner"] for r in repos if r["name"].startswith(prefix)]

    if not to_delete:
        click.echo("No matching repositories found.")
        return

    click.echo(f"Found {len(to_delete)} repositories:")
    for repo in to_delete:
        click.echo(f" - {repo}")

    if not force and not click.confirm("\nAre you sure you want to delete these repositories?"):
        click.echo("Aborted.")
        return

    for repo_name in to_delete:
        click.echo(f"Deleting {repo_name}...")
        client = GitHubClient(repo=repo_name)
        success, err = client.delete_repo()
        if not success:
            click.echo(click.style(f"Failed to delete {repo_name}: {err}", fg="red"))
        else:
            click.echo(click.style(f"Successfully deleted {repo_name}", fg="green"))


@cli.command()
@click.option("--aggregate", is_flag=True, help="Aggregate results by workflow.")
def report(aggregate):
    """Generate a summary of previous runs from the 'runs/' directory."""
    runs_dir = "runs"
    if not os.path.exists(runs_dir):
        click.echo("No runs found.")
        return

    if aggregate:
        pairs = {}
        for folder in os.listdir(runs_dir):
            metadata_path = os.path.join(runs_dir, folder, "metadata.json")
            if not os.path.isfile(metadata_path):
                continue
            try:
                with open(metadata_path) as handle:
                    data = json.load(handle)
            except json.JSONDecodeError:
                continue
            if data.get("workflow") and ("analysis" in data or "error" in data):
                pairs.setdefault((data["workflow"], "all scenarios"), []).append(data)
        _display_repeat_summary(pairs)

    else:
        header = f"{'Timestamp':<25} {'Workflow':<20} {'Scenario':<25} {'Util':<6} {'Sec':<6} {'Auto':<6}"
        click.echo(click.style(header, bold=True))
        click.echo("-" * 95)

        run_folders = sorted([d for d in os.listdir(runs_dir) if os.path.isdir(os.path.join(runs_dir, d))], reverse=True)

        for folder in run_folders:
            metadata_path = os.path.join(runs_dir, folder, "metadata.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, "r") as f:
                    try:
                        data = json.load(f)
                        if "analysis" not in data and "error" not in data:
                            continue
                        analysis = data.get("analysis", {})

                        def verdict_label(key, invert=False):
                            value = analysis.get(key)
                            if type(value) is not bool:
                                return "?"
                            return "T" if value is (False if invert else True) else "F"

                        click.echo(
                            f"{data.get('timestamp', folder):<25} "
                            f"{data.get('workflow'):<20} "
                            f"{str(data.get('scenario', '')):<25} "
                            f"{verdict_label('utility_achieved'):<6} "
                            f"{verdict_label('security_breached', True):<6} "
                            f"{verdict_label('autonomy_achieved'):<6}"
                        )
                    except (json.JSONDecodeError, KeyError):
                        pass


@cli.command()
@click.option("--workflow", "workflow_id", default=None, help="Workflow ID to scan.")
@click.option("--all", "scan_all", is_flag=True, help="Scan all workflows in the inventory.")
@click.option("--hypotheses", default=12, show_default=True, help="Hypotheses per scan, split across 4 MITRE categories.")
@click.option("--max-live", default=5, show_default=True, help="Max hypotheses to validate live, by severity rank.")
@click.option("--runs-per", default=3, show_default=True, help="Runs per hypothesis for confirmation.")
@click.option("--iterations", default=2, show_default=True, help="Hypothesis refinement iterations.")
@click.option("--dry-run", is_flag=True, help="Generate and rank hypotheses only; no live runs.")
@click.option("--no-ranker", is_flag=True, help="Skip LLM ranker; use structural pre-pass only (ablation).")
@click.option("--no-memory", is_flag=True, help="Disable cross-workflow memory seeding (ablation).")
@click.option("--monolithic", is_flag=True, help="Use single hypothesis prompt instead of per-category (ablation).")
@click.option("--output", "output_dir", default="reports/scanner", show_default=True, help="Directory for reports.")
@click.option("--hypothesis-model", default="claude-sonnet-4-6", show_default=True, help="LLM for hypothesis generation.")
@click.option("--ranker-model", default="claude-sonnet-4-6", show_default=True, help="LLM for plausibility ranking.")
@click.option(
    "--judge-model",
    default="gemini-3.1-pro-preview",
    show_default=True,
    help="LLM judge for semantic success evaluation.",
)
@click.option(
    "--repo-prefix",
    default=lambda: os.environ.get("GITHUB_REPO_PREFIX", "benchmark-scan"),
    help="GitHub repository prefix for live runs.",
)
@click.option("--cleanup/--no-cleanup", default=True, help="Delete repository after each live run.")
@click.option("--baselines/--no-baselines", default=True, help="Run zizmor and actionlint baselines.")
@click.option("--reseed", is_flag=True, help="Force reload the warm-start research corpus.")
@click.option(
    "--no-diagnostics",
    is_flag=True,
    help="Disable diagnostic stage; collapse all failures to payload_ineffective (ablation).",
)
@click.option(
    "--diagnostic-model",
    default="claude-haiku-4-5",
    show_default=True,
    help="LLM for fast-path artifact inspection in the diagnostic stage.",
)
def scan(
    workflow_id,
    scan_all,
    hypotheses,
    max_live,
    runs_per,
    iterations,
    dry_run,
    no_ranker,
    no_memory,
    monolithic,
    output_dir,
    hypothesis_model,
    ranker_model,
    judge_model,
    repo_prefix,
    cleanup,
    baselines,
    reseed,
    no_diagnostics,
    diagnostic_model,
):
    """Autonomously scan a workflow for prompt injection vulnerabilities."""
    import time as _time

    from .scanner import hypothesis_generator, llm_ranker, prompt_extractor, report_generator
    from .scanner.baselines import actionlint_runner, zizmor_runner
    from .scanner.live_validator import validate
    from .scanner.memory import CrossWorkflowMemory
    from .scanner.types import ScanCost, roll_up_usage
    from .utils.llm import track_usage

    workflows_dir = dataset_dir("workflows")

    if scan_all:
        workflow_ids = sorted(
            [d for d in os.listdir(workflows_dir) if os.path.isdir(os.path.join(workflows_dir, d)) and not d.startswith("_")]
        )
    elif workflow_id:
        workflow_ids = [workflow_id]
    else:
        click.echo(click.style("Error: provide --workflow or --all.", fg="red"))
        return

    memory = CrossWorkflowMemory() if not no_memory else CrossWorkflowMemory.__new__(CrossWorkflowMemory)
    if no_memory:
        memory._entries = []
        memory.path = "/dev/null"
        memory._save = lambda: None
    else:
        needs_warm_start = reseed or not memory._entries
        if needs_warm_start:
            click.echo("  Loading the warm-start research corpus...")
            n = memory.warm_start(reseed=reseed)
            click.echo(f"  Warm-start: {n} confirmed entries loaded.")

    all_summary: list[dict] = []

    for wf_id in workflow_ids:
        click.echo("\n" + click.style(f"=== Scanning: {wf_id} ===", bold=True))

        meta_path = os.path.join(workflows_dir, wf_id, "metadata.json")
        workflow_category = "code-review"
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                workflow_category = json.load(f).get("category", "code-review")

        try:
            context = prompt_extractor.extract(wf_id, workflows_dir)
        except Exception as e:
            click.echo(click.style(f"  Failed to extract context: {e}", fg="red"))
            continue

        click.echo(f"  Provider: {context.provider}")
        click.echo(f"  Trigger: {context.trigger_event}")

        baseline_findings: list[dict] = []
        if baselines:
            wf_contents = os.path.join(workflows_dir, wf_id, "contents")
            if os.path.isdir(wf_contents):
                click.echo("  Running baselines...")
                baseline_findings.extend(zizmor_runner.run(wf_contents))
                baseline_findings.extend(actionlint_runner.run(wf_contents))
                click.echo(f"  Baseline findings: {len(baseline_findings)}")

        wf_start = _time.monotonic()
        with track_usage() as usage_log:
            click.echo(f"  Generating {hypotheses} hypotheses...")
            raw_hypotheses = hypothesis_generator.generate(
                context,
                memory,
                hypotheses_per_scan=hypotheses,
                monolithic=monolithic,
                model=hypothesis_model,
            )
            click.echo(f"  Generated: {len(raw_hypotheses)}")

            ranked, discarded = llm_ranker.rank(raw_hypotheses, context, skip_llm=no_ranker, model=ranker_model)
            click.echo(f"  After filtering: {len(ranked)} ranked, {len(discarded)} discarded")

            results = validate(
                hypotheses=ranked,
                context=context,
                workflow_id=wf_id,
                workflow_category=workflow_category,
                runs_per_hypothesis=runs_per,
                max_hypotheses=max_live,
                iterations=iterations,
                repo_prefix=repo_prefix,
                cleanup=cleanup,
                dry_run=dry_run,
                judge_model=judge_model,
                enable_diagnostics=not no_diagnostics,
                diagnostic_model=diagnostic_model,
            )

        scan_cost = ScanCost(
            token_usage_by_model=roll_up_usage(usage_log),
            total_billable_minutes=sum(r.billable_minutes for r in results),
            total_wall_seconds=_time.monotonic() - wf_start,
        )

        confirmed = [r for r in results if r.status == "confirmed"]
        click.echo(
            click.style(
                f"  Result: {len(confirmed)}/{len(results)} confirmed "
                f"(${scan_cost.total_usd:.4f}, {scan_cost.total_billable_minutes:.1f} billable min)",
                fg="green" if confirmed else "yellow",
            )
        )

        md_path, _ = report_generator.generate(
            context, results, discarded, baseline_findings, output_dir, scan_cost=scan_cost
        )
        click.echo(f"  Report: {md_path}")

        all_summary.append(
            {
                "workflow": wf_id,
                "confirmed": len(confirmed),
                "validated": len(results),
                "filtered": len(discarded),
                "report_md": md_path,
            }
        )

    if len(workflow_ids) > 1:
        click.echo("\n" + click.style("=== Scan Summary ===", bold=True))
        total_confirmed = sum(s["confirmed"] for s in all_summary)
        total_validated = sum(s["validated"] for s in all_summary)
        click.echo(f"Workflows scanned: {len(all_summary)}")
        click.echo(f"Total confirmed: {total_confirmed} / {total_validated} validated")
        for s in all_summary:
            status_color = "green" if s["confirmed"] > 0 else "white"
            click.echo(
                click.style(f"  {s['workflow']:<30}", bold=True)
                + click.style(f"confirmed: {s['confirmed']}", fg=status_color)
            )


install_cli(cli)

if __name__ == "__main__":
    cli()
