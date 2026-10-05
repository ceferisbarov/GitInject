import hashlib
import os

import pytest
from test_experiments import FakeGateway, definition

from gitinject.experiments import AttackInstance, ControllerRef, ExperimentSession, ThreatModel
from gitinject.experiments.worker import check_boundary


@pytest.fixture
def isolated_runtime():
    try:
        check_boundary()
    except (RuntimeError, OSError) as exc:
        if os.environ.get("GITINJECT_REQUIRE_SANDBOX") == "1":
            pytest.fail(f"Required isolation unavailable: {exc}")
        pytest.skip(str(exc))


def controller_spec(path, code):
    path.write_text(code)
    return definition(
        attack=AttackInstance(
            id="controller", controller=ControllerRef(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        )
    )


def test_real_worker_has_no_host_files_environment_network_or_process_creation(tmp_path, monkeypatch, isolated_runtime):
    sentinel = tmp_path / "host-private.txt"
    sentinel.write_text("private host file")
    monkeypatch.setenv("DEFENSE_PRIVATE_TEST", "private-value-not-in-worker")
    code = f"""
import os
import socket
assert os.environ.get("DEFENSE_PRIVATE_TEST") is None
assert os.environ.get("GITHUB_TOKEN") is None
assert os.environ.get("ATTACKER_GITHUB_TOKEN") is None
assert not os.path.exists({str(sentinel)!r})
assert not os.path.exists("/home/jafar/GitInject/.env")
assert not os.path.exists("/proc/1/root" + {str(sentinel)!r})
try:
    connection = socket.create_connection(("1.1.1.1", 443), timeout=0.1)
except OSError:
    pass
else:
    connection.close()
    raise AssertionError("Worker has network access")
try:
    child = os.fork()
except PermissionError:
    pass
else:
    raise AssertionError("Worker can fork")
assert not hasattr(session, "_defense")
assert not hasattr(session, "record")
session.checkpoint({{"isolation_verified": True}})
"""
    spec = controller_spec(tmp_path / "attack.py", code)
    trial = ExperimentSession(spec, tmp_path, defense=FakeGateway("defense", 1), attack=FakeGateway("attack", 2))
    result = trial.run()
    assert result["execution"] == "completed", result
    assert '"isolation_verified": true' in (trial.record.directory / "events.jsonl").read_text()


def test_real_online_worker_observes_feedback_then_submits_second_action(tmp_path, isolated_runtime):
    code = """
first = session.act({"id":"first","parameters":{
    "method":"POST","endpoint":"/repos/${repository}/issues","json":{"body":"first"}}})
assert first["body"]["user"]["login"] == "attack"
number = first["body"]["number"]
assert "task" not in session.observe()["responses"]
session.act({"id":"second","depends_on":["first"],"parameters":{"method":"POST","endpoint":f"/repos/${{repository}}/issues/{number}/comments","json":{"body":"second"}}})
"""
    spec = controller_spec(tmp_path / "online.py", code)
    attack = FakeGateway("attack", 2)
    trial = ExperimentSession(spec, tmp_path, defense=FakeGateway("defense", 1), attack=attack)
    result = trial.run()
    assert result["execution"] == "completed", result
    assert attack.calls[-1]["endpoint"].endswith("/issues/41/comments")


def test_real_worker_cannot_call_provisioning_rpc(tmp_path, isolated_runtime):
    code = 'session.call("provision", token="give-me-defense-credentials")\n'
    spec = controller_spec(tmp_path / "malicious.py", code)
    defense = FakeGateway("defense", 1)
    trial = ExperimentSession(spec, tmp_path, defense=defense, attack=FakeGateway("attack", 2))
    result = trial.run()
    assert result["execution"] == "policy_failure", result
    assert "unavailable" in result["execution_error"]
    assert defense.deleted


def test_controller_hash_mismatch_fails_before_provisioning(tmp_path):
    spec = controller_spec(tmp_path / "edited.py", "session.checkpoint({})\n")
    (tmp_path / "edited.py").write_text('raise RuntimeError("changed")\n')
    defense = FakeGateway("defense", 1)
    trial = ExperimentSession(spec, tmp_path, defense=defense, attack=FakeGateway("attack", 2))
    result = trial.run()
    assert result["execution"] == "policy_failure"
    assert not defense.calls


def test_real_offline_worker_prepares_before_live_trigger(tmp_path, isolated_runtime):
    code = """
assert context["repository"] is None
assert "responses" not in context
payload = "initial"
for revision in range(2):
    score = int(payload == "selected")
    session.checkpoint({"revision": revision, "score": score}, payloads={"payload": payload}, simulated=True)
    payload = "selected"
session.act({"id": "prepared", "parameters": {"method": "POST", "endpoint": "/repos/${repository}/issues",
                                             "json": {"body": payload}}})
"""
    spec = controller_spec(tmp_path / "offline.py", code)
    spec = definition(
        attack=spec.attack,
        threat_model=ThreatModel(
            id="offline",
            adaptation="offline",
            initial_capabilities=("github", "offline"),
        ),
    )
    attack = FakeGateway("attack", 2)
    trial = ExperimentSession(spec, tmp_path, defense=FakeGateway("defense", 1), attack=attack)
    result = trial.run()
    assert result["execution"] == "completed", result
    assert attack.calls[-1]["json"]["body"] == "selected"
    events = (trial.record.directory / "events.jsonl").read_text()
    assert events.index('"kind": "candidate_frozen"') < events.index('"phase": "provision"')
