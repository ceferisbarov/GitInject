"""Trace replay, adaptive reruns, captured-evidence evaluation, and drift reporting."""

import hashlib
import json
import re
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


REFERENCE_KEYS = {
    "id",
    "node_id",
    "number",
    "sha",
    "full_name",
    "html_url",
    "url",
    "nameWithOwner",
    "databaseId",
    "issue_number",
    "pull_number",
    "run_id",
    "comment_id",
    "repository",
    "base",
    "head",
}
PAYLOAD_KEYS = {"body", "title", "content", "message", "data"}


def _bind(mapping, key, new):
    if key in mapping and mapping[key] != new:
        mapping[key] = None
    else:
        mapping[key] = new


def _mapping(old, new, mapping):
    if isinstance(old, dict) and isinstance(new, dict):
        for key in old.keys() & new.keys():
            if key in REFERENCE_KEYS and isinstance(old[key], (str, int)) and isinstance(new[key], type(old[key])):
                _bind(mapping, (type(old[key]).__name__, str(old[key])), new[key])
            _mapping(old[key], new[key], mapping)
    elif isinstance(old, list) and isinstance(new, list):
        # Lists have no reliable positional identity. Require explicit response bindings.
        return


def _response_routes(action, old, new, mapping):
    """Bind numeric REST resources to their full repository and resource path."""
    if action.get("transport", "rest") != "rest":
        return
    endpoint = action["parameters"].get("endpoint", "")
    old_body, new_body = old.get("body", {}), new.get("body", {})
    if not isinstance(old_body, dict) or not isinstance(new_body, dict):
        return
    route = re.fullmatch(r"(https://api.github.com)?(/repos/[^/]+/[^/]+/(issues|pulls|comments|actions/runs))", endpoint)
    if route:
        key = "number" if route[3] in {"issues", "pulls"} else "id"
        if key in old_body and key in new_body:
            original = f"{route[2]}/{old_body[key]}"
            fresh = _route(route[2], mapping) + f"/{new_body[key]}"
            _bind(mapping, ("route", original), fresh)


def _route(value, mapping):
    # Replace complete route segments only, never strings inside payloads.
    for (kind, old), new in sorted(mapping.items(), key=lambda item: len(item[0][1]), reverse=True):
        if kind != "route":
            continue
        pattern = re.escape(old) + r"(?=/|\?|$)"
        if re.search(pattern, value):
            require(new is not None, f"Ambiguous replay resource: {old}; use a symbolic response binding")
            return re.sub(pattern, lambda _: new, value, count=1)
    return value


def remap(value, mapping, key=""):
    if key in PAYLOAD_KEYS:
        return value
    if isinstance(value, str) and key == "query":
        for (kind, old), new in mapping.items():
            if kind == "str" and new != old and len(old) >= 8:
                require(old not in value, "Literal GraphQL resource requires a symbolic variable binding for replay")
        return value
    if isinstance(value, dict):
        return {k: remap(v, mapping, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [remap(item, mapping, key) for item in value]
    if isinstance(value, str) and key == "endpoint":
        value = value.replace("${repository}", mapping.get(("original_repository", ""), "${repository}"))
        fresh = _route(value, mapping)
        # If a captured numeric route has no contextual resource binding, don't guess.
        original_resource = re.search(r"/repos/[^/]+/[^/]+/(?:issues|pulls|comments|actions/runs)/(\d+)(?=/|\?|$)", value)
        if original_resource:
            original_path = original_resource.group(0)
            require(("route", original_path) in mapping, "Unbound replay resource; use a symbolic response binding")
        return fresh
    if isinstance(value, str) and "${" in value:
        return value
    if isinstance(value, (str, int)):
        reference = key in REFERENCE_KEYS or key.endswith("Id") or key.endswith("_id")
        if type(value) is int and not reference:
            return value
        binding = (type(value).__name__, str(value))
        if binding in mapping:
            require(mapping[binding] is not None, "Ambiguous replay identifier; use a symbolic response binding")
            require(
                reference or mapping[binding] == value,
                "Unbound replay identifier field; use a symbolic response binding",
            )
            return mapping[binding]
    return value


def _replay_action(action, mapping):
    return {
        **action,
        "parameters": remap(action["parameters"], mapping),
        "subject": remap(action.get("subject", {}), mapping),
    }


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
        old_repo = inspection["manifest"]["effective_repository"]
        mapping = {
            ("route", f"/repos/{old_repo}"): f"/repos/{session.repository}",
            ("str", old_repo): session.repository,
            ("original_repository", ""): old_repo,
        }
        task_id = data["task_trigger"]["id"]
        _mapping(old_responses.get(task_id, {}), session._responses[task_id], mapping)
        task_event = next(e for e in inspection["events"] if e["kind"] == "action_planned" and e["action"]["id"] == task_id)
        _response_routes(task_event["resolved"], old_responses.get(task_id, {}), session._responses[task_id], mapping)
        # Polls are implementation details of a wait, not independent replay actions.
        waits = [e for e in inspection["events"] if e["kind"] == "wait_complete"]
        poll_ids = set()
        for wait in waits:
            prefix = wait["action"]["id"] + "-poll-"
            poll_ids.update(
                e["action"]["id"]
                for e in inspection["events"]
                if e["kind"] == "action_planned" and re.fullmatch(re.escape(prefix) + r"\d+", e["action"]["id"])
            )
        for event in inspection["events"]:
            if event["kind"] == "authority_acquired":
                session.use_acquired_authority(event["source"])
                continue
            if event["kind"] == "wait_complete":
                require("[REDACTED]" not in canonical(event["action"]), "Sensitive redacted wait cannot be replayed")
                action = Action.from_dict(_replay_action(event["action"], mapping))
                response = session.act(action)
                require(
                    event["response"].get("timed_out") or not response.get("timed_out"),
                    "Replay wait condition did not hold in the fresh trial",
                )
                _mapping(event["response"], response, mapping)
                continue
            if event["kind"] != "action_planned" or event["actor"] != "attack" or event["action"]["id"] in poll_ids:
                continue
            action = _replay_action(event["action"], mapping)
            require(
                "[REDACTED]" not in canonical(action), "Sensitive redacted action cannot be replayed without a new candidate"
            )
            response = session.act(Action.from_dict(action))
            old_response = old_responses.get(action["id"], {})
            _mapping(old_response, response, mapping)
            _response_routes(event["resolved"], old_response, response, mapping)
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
