"""CLI for experiment definitions; planning never constructs authenticated clients."""

import json
from pathlib import Path

import click

from .contracts import EvaluationContract, load_spec
from .session import ExperimentSession


def plan(spec):
    requirements = {"defense": "GITHUB_TOKEN or gh auth token"}
    if spec.attack:
        requirements["attack"] = "ATTACKER_GITHUB_TOKEN (distinct account)"
    references = list(spec.target.credential_refs.values())
    references += [c.credential.environment for c in spec.provisioning.changes if c.credential]
    static = []
    if spec.attack:
        from .evaluation import MISSING, lookup

        conditions = spec.attack.preconditions + (spec.attack.method.applicability if spec.attack.method else ())
        for condition in conditions:
            if condition.phase == "static":
                value = lookup(spec.target.to_dict(), condition.path)
                static.append(
                    {
                        "id": condition.id,
                        "status": "unknown"
                        if value is MISSING
                        else ("applicable" if value == condition.expected else "inapplicable"),
                    }
                )
    return {
        "id": spec.id,
        "revision": spec.revision,
        "target_revision": spec.target.revision,
        "evaluation_revision": spec.evaluation.revision,
        "requirements": requirements,
        "credential_references": sorted(set(references)),
        "static_applicability": static,
        "runtime_applicability": "requires a provisioned trial",
        "budgets": spec.budgets.to_dict(),
        "controller_boundary": "Linux Bubblewrap required"
        if spec.attack and spec.attack.controller
        else "declarative actions",
        "resource_boundary": spec.threat_model.scope,
        "fresh_repository": True,
    }


def _emit(value):
    click.echo(json.dumps(value, indent=2))


def _read(path):
    try:
        return load_spec(path)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise click.ClickException(str(exc)) from exc


@click.group()
def experiment():
    """Plan and execute versioned two-account experiments."""


@experiment.command("list")
@click.argument("directory", type=click.Path(exists=True, file_okay=False), default="examples/experiments")
def list_experiments(directory):
    """List JSON experiment definitions without executing controller code."""
    for path in sorted(Path(directory).glob("*.json")):
        spec = _read(path)
        click.echo(f"{spec.id}\t{path}\t{spec.revision}")


@experiment.command("validate")
@click.argument("definition", type=click.Path(exists=True, dir_okay=False))
def validate(definition):
    """Validate serializable definitions without credentials or model calls."""
    _emit({"valid": True, **plan(_read(definition))})


@experiment.command("dry-run")
@click.argument("definition", type=click.Path(exists=True, dir_okay=False))
def dry_run(definition):
    """Report known applicability, budgets and requirements without mutations."""
    _emit(plan(_read(definition)))


@experiment.command("run")
@click.argument("definition", type=click.Path(exists=True, dir_okay=False))
@click.option("--workspace", type=click.Path(file_okay=False), default=".")
def run(definition, workspace):
    """Execute a fresh trial and save its manifest, actions and evidence."""
    result = ExperimentSession(_read(definition), workspace).run()
    _emit(result)
    if result["execution"] != "completed":
        raise click.ClickException("Experiment did not complete; inspect the saved result")


@experiment.command("suite")
@click.argument("definitions", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--dry-run", is_flag=True)
@click.option("--workspace", type=click.Path(file_okay=False), default=".")
def suite(definitions, dry_run, workspace):
    """Plan or execute experiments sequentially within their trial budgets."""
    specs = [_read(path) for path in definitions]
    counts = {}
    for spec in specs:
        identity = spec.id
        counts[identity] = counts.get(identity, 0) + 1
        if counts[identity] > spec.budgets.trials:
            raise click.ClickException(f"Trial budget exhausted for {identity}")
    if dry_run:
        _emit([plan(spec) for spec in specs])
    else:
        results = [ExperimentSession(spec, workspace).run() for spec in specs]
        _emit(results)
        if any(result["execution"] != "completed" for result in results):
            raise click.ClickException("One or more experiments did not complete; inspect saved results")


@experiment.command("replay")
@click.argument("attempt", type=click.Path(exists=True, file_okay=False))
@click.option("--mode", type=click.Choice(["inspect", "trace", "controller", "evaluate"]), default="inspect")
@click.option("--allow-drift", is_flag=True)
@click.option("--workspace", type=click.Path(file_okay=False), default=".")
@click.option("--evaluation", type=click.Path(exists=True, dir_okay=False))
def replay(attempt, mode, allow_drift, workspace, evaluation):
    """Inspect hashes/drift, replay actions, rerun a controller, or reevaluate evidence."""
    from .replay import inspect_attempt, reevaluate, replay_trace, rerun_controller

    try:
        if mode == "inspect":
            inspection = inspect_attempt(attempt, workspace=workspace)
            result = {
                "attempt_id": inspection["manifest"]["attempt_id"],
                "hashes_verified": True,
                "drift": inspection["drift"],
            }
        elif mode == "evaluate":
            contract = EvaluationContract.from_dict(json.loads(Path(evaluation).read_text())) if evaluation else None
            result = reevaluate(attempt, contract=contract)
        elif mode == "trace":
            result = replay_trace(attempt, workspace, allow_drift=allow_drift)
        else:
            result = rerun_controller(attempt, workspace, allow_drift=allow_drift)
        _emit(result)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


def install_cli(root):
    legacy = click.Group("legacy", help="Original workflow/scenario/scanner engine. No isolated-controller guarantees.")
    for name in ("run", "run-suite", "scan", "optimize", "preflight", "cleanup", "report"):
        command = root.commands.pop(name, None)
        if command:
            legacy.add_command(command, name)
    root.add_command(legacy)
    root.add_command(experiment)
    root.commands["list"].add_command(experiment.commands["list"], "experiments")
