"""Trace replay, adaptive reruns, captured-evidence evaluation, and drift reporting."""

import hashlib
import json
from pathlib import Path

from .contracts import Action, ExperimentSpec, canonical, digest, require
from .evaluation import evaluate
from .session import ExperimentSession


def _inside(directory, relative):
    destination = (directory / relative).resolve()
    require(directory.resolve() in destination.parents, "Artifact path escapes attempt directory")
    return destination


def inspect_attempt(directory, *, workspace="."):
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    require(manifest.get("schema_version") == 2, "Only experiment v2 manifests are supported")
    spec = ExperimentSpec.from_dict(manifest["spec"])
    require(spec.revision == manifest["experiment_revision"], "Experiment definition hash mismatch")
    require(
        spec.target.revision == manifest["target_revision"] and spec.evaluation.revision == manifest["evaluation_revision"],
        "Frozen target or evaluator hash mismatch",
    )
    for label, entries in manifest["inputs"].items():
        for relative, expected in entries.items():
            path = _inside(directory, f"inputs/{label}/{relative}")
            require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, f"Input hash mismatch: {relative}")
    events = [json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()]
    previous = None
    for event in events:
        actual = event.get("event_hash")
        data = {k: v for k, v in event.items() if k != "event_hash"}
        require(event.get("previous_hash") == previous and digest(data) == actual, "Execution journal hash mismatch")
        previous = actual
        if event["kind"] == "artifact":
            path = _inside(directory, event["path"])
            require(hashlib.sha256(path.read_bytes()).hexdigest() == event["sha256"], "Artifact hash mismatch")
    require(previous == manifest.get("journal_head"), "Journal tail is missing or changed")
    drift = []
    environment = manifest.get("environment", {})
    if environment:
        import sys
        from importlib.metadata import distributions

        dependencies = {d.metadata["Name"]: d.version for d in distributions() if d.metadata.get("Name")}
        if environment["python"] != sys.version:
            drift.append("Python runtime changed")
        if environment["dependencies"] != dependencies:
            drift.append("installed dependency versions changed")
    current_lock = Path(workspace) / "uv.lock"
    captured_lock = manifest["inputs"].get("dependencies", {}).get("uv.lock")
    if captured_lock and (
        not current_lock.is_file() or hashlib.sha256(current_lock.read_bytes()).hexdigest() != captured_lock
    ):
        drift.append("dependency lockfile changed or unavailable")
    from . import session as session_module

    source_root = Path(session_module.__file__).parent
    for relative, expected in manifest.get("implementation_hashes", {}).items():
        path = source_root / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            drift.append(f"implementation changed: {relative}")
    for event in events:
        if event["kind"] == "action_receipt" and event.get("uncertain"):
            drift.append("trace contains an uncertain mutation; reconcile before replay")
    return {"manifest": manifest, "spec": spec, "events": events, "drift": drift}


def _mapping(old, new, mapping):
    if isinstance(old, dict) and isinstance(new, dict):
        for key in old.keys() & new.keys():
            if key in {"id", "node_id", "number", "sha", "full_name", "html_url", "url", "nameWithOwner", "databaseId"}:
                if isinstance(old[key], (str, int)) and isinstance(new[key], type(old[key])):
                    mapping[(type(old[key]).__name__, str(old[key]))] = new[key]
            _mapping(old[key], new[key], mapping)
    elif isinstance(old, list) and isinstance(new, list):
        for left, right in zip(old, new):
            _mapping(left, right, mapping)


def remap(value, mapping, key=""):
    if isinstance(value, dict):
        return {k: remap(v, mapping, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [remap(item, mapping, key) for item in value]
    if isinstance(value, str):
        if ("str", value) in mapping:
            return mapping[("str", value)]
        for (kind, old), new in sorted(mapping.items(), key=lambda item: len(item[0][1]), reverse=True):
            if kind == "str" and isinstance(new, str):
                value = value.replace(old, new)
            elif kind == "int":
                for resource in ("issues", "pulls", "runs", "comments"):
                    value = value.replace(f"/{resource}/{old}/", f"/{resource}/{new}/")
                    if value.endswith(f"/{resource}/{old}"):
                        value = value[: -len(old)] + str(new)
        return value
    if type(value) is int and key in {"id", "number", "issue_number", "pull_number", "run_id", "comment_id"}:
        return mapping.get(("int", str(value)), value)
    return value


def replay_trace(directory, workspace=".", *, allow_drift=False, defense=None, attack=None):
    inspection = inspect_attempt(directory, workspace=workspace)
    require(
        not any(e.get("uncertain") for e in inspection["events"]),
        "Uncertain operations must be reconciled before trace replay",
    )
    require(allow_drift or not inspection["drift"], f"Environment drift: {inspection['drift']}")
    data = inspection["spec"].to_dict()
    require(data["attack"] is not None, "Trace replay requires an attack; rerun a benign experiment instead")
    data["parent_attempt"] = inspection["manifest"]["attempt_id"]
    data["attack"]["actions"] = []
    data["attack"]["controller"] = None
    session = ExperimentSession(ExperimentSpec.from_dict(data), workspace, defense=defense, attack=attack)
    session.record.event("replay", mode="trace", parent_attempt=data["parent_attempt"], drift=inspection["drift"])
    old_responses = {e["action_id"]: e.get("response", {}) for e in inspection["events"] if e["kind"] == "action_receipt"}
    try:
        session.initialize()
        mapping = {("str", inspection["manifest"]["effective_repository"]): session.repository}
        _mapping(old_responses.get(data["task_trigger"]["id"], {}), session._responses[data["task_trigger"]["id"]], mapping)
        for event in inspection["events"]:
            if event["kind"] == "authority_acquired":
                session.use_acquired_authority(event["source"])
                continue
            if event["kind"] == "wait_complete":
                original = event["action"]["id"]
                response = remap(event["response"], mapping)
                session._responses[original] = response
                session._response_roles[original] = "attack"
                session.record.event(
                    "wait_complete", actor="attack", action=remap(event["action"], mapping), response=response
                )
                continue
            if event["kind"] != "action_planned" or event["actor"] != "attack":
                continue
            action = remap(event["action"], mapping)
            require(
                "[REDACTED]" not in canonical(action), "Sensitive redacted action cannot be replayed without a new candidate"
            )
            response = session.act(Action.from_dict(action))
            _mapping(old_responses.get(action["id"], {}), response, mapping)
        return session.finish()
    except Exception as exc:
        if not session._closed:
            session._failure(exc)
            session._cleanup()
            session._closed = True
            session._save_result()
        return session.redactor(session.result)


def rerun_controller(directory, workspace=".", *, allow_drift=False, **gateways):
    inspection = inspect_attempt(directory, workspace=workspace)
    require(allow_drift or not inspection["drift"], f"Environment drift: {inspection['drift']}")
    data = inspection["spec"].to_dict()
    data["parent_attempt"] = inspection["manifest"]["attempt_id"]
    if data["attack"] and data["attack"]["controller"]:
        original = data["attack"]["controller"]
        original["path"] = str(Path(directory).resolve() / "inputs/controller" / Path(original["path"]).name)
    session = ExperimentSession(ExperimentSpec.from_dict(data), workspace, **gateways)
    session.record.event("replay", mode="controller", parent_attempt=data["parent_attempt"], drift=inspection["drift"])
    return session.run()


def reevaluate(directory, *, contract=None):
    inspection = inspect_attempt(directory)
    directory = Path(directory)
    contract = contract or inspection["spec"].evaluation
    if contract.revision != inspection["spec"].evaluation.revision:
        require(
            contract.parent_revision == inspection["spec"].evaluation.revision,
            "Revised evaluation must link to its parent revision",
        )
    evidence = json.loads((directory / "artifacts/evidence.json").read_text())
    original_result = json.loads((directory / "artifacts/result.json").read_text())
    result = evaluate(contract, evidence, original_result.get("invocation"), redacted=True)
    result["drift"] = inspection["drift"]
    result["parent_attempt"] = inspection["manifest"]["attempt_id"]
    result["limitations"] = "Redacted raw secrets are unavailable; sensitive checks may be unknown"
    return result
