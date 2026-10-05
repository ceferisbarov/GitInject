"""Public iterative trial API and the privileged experiment lifecycle."""

import base64
import hashlib
import json
import os
import re
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from importlib.metadata import distributions
from pathlib import Path

from ..run_record import RunRecord
from .contracts import Action, ExperimentSpec, canonical, plain, require
from .evaluation import MISSING, evaluate, lookup
from .gateway import AmbiguousOperation, Gateway, PolicyError, Redactor


class SessionStopped(RuntimeError):
    pass


def ensure(condition, message):
    if not condition:
        raise RuntimeError(message)


class ExperimentRecord(RunRecord):
    def __init__(self, workspace, spec, redactor):
        self.redactor = redactor
        self._journal_head = None
        super().__init__(str(workspace), spec)
        self.manifest.update(
            schema_version=2,
            experiment_revision=spec.revision,
            target_revision=spec.target.revision,
            evaluation_revision=spec.evaluation.revision,
            threat_model_revision=spec.threat_model.revision,
        )
        self.manifest["environment"] = {
            "python": sys.version,
            "dependencies": {d.metadata["Name"]: d.version for d in distributions() if d.metadata.get("Name")},
        }
        self.manifest["implementation_hashes"] = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob("*.py")
        }
        self.save_manifest()
        self.snapshot("implementation", Path(__file__).parent)
        self.snapshot("shared-runtime", Path(__file__).parent.parent / "run_record.py")
        lockfile = Path(workspace) / "uv.lock"
        if lockfile.is_file():
            self.snapshot("dependencies", lockfile)

    def save_manifest(self):
        from ..run_record import write_json

        write_json(self.directory / "manifest.json", self.redactor(self.manifest))

    def event(self, kind, **data):
        from .contracts import digest

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            **self.redactor(data),
            "previous_hash": self._journal_head,
        }
        entry["event_hash"] = digest(entry)
        with (self.directory / "events.jsonl").open("a") as handle:
            handle.write(json.dumps(entry, allow_nan=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._journal_head = entry["event_hash"]
        self.manifest["journal_head"] = self._journal_head
        self.save_manifest()

    def artifact(self, name, value):
        return super().artifact(name, self.redactor(value))

    def snapshot(self, label, source, *, prefix=""):
        source = Path(source)
        for path in sorted(source.rglob("*")) if source.is_dir() else [source]:
            if path.is_file():
                content = path.read_bytes()
                if any(secret.encode() in content for secret in self.redactor.secrets):
                    raise PolicyError("Input contains credentials; use credential references")
        super().snapshot(label, source, prefix=prefix)


class ExperimentSession:
    """Trusted host API. Untrusted controllers receive only the worker RPC protocol."""

    def __init__(self, spec, workspace=".", *, defense=None, attack=None, clock=time.monotonic):
        self.spec = ExperimentSpec.from_dict(spec.to_dict())
        self.workspace = Path(workspace)
        self.clock = clock
        self.started = clock()
        self.deadline = self.started + self.spec.budgets.elapsed_seconds
        self._defense = defense
        self._attack = attack
        self._gateways = {}
        self._cleanup_gateways = {}
        self._active_attack_identity = None
        self._resources = {}
        self._initial_repositories = {}
        self._responses = {}
        self._response_roles = {}
        self._subjects = {}
        self._cancelled = False
        self._closed = False
        self._initialized = False
        self.action_count = 0
        self.model_calls = 0
        self.model_cost = 0
        self.identities = {}
        self.repository = None
        self.invocation = None
        self.result = {
            "applicability": "unknown",
            "execution": "pending",
            "invocation": None,
            "utility": None,
            "security": None,
            "evaluation": "pending",
        }
        secrets = [os.environ.get("GITHUB_TOKEN"), os.environ.get("ATTACKER_GITHUB_TOKEN")]
        for gateway in (defense, attack):
            if gateway is not None:
                secrets.append(getattr(gateway, "_token", None))
        environments = list(self.spec.target.credential_refs.values())
        environments += [c.credential.environment for c in self.spec.provisioning.changes if c.credential]
        environments += [c["credential_environment"] for c in self.spec.evaluation.checks if "credential_environment" in c]
        secrets += [os.environ.get(name) for name in environments]
        self.redactor = Redactor(secrets)
        require(
            self.redactor(canonical(self.spec)) == canonical(self.spec),
            "Private credentials cannot be embedded in experiment definitions",
        )
        self.record = ExperimentRecord(self.workspace, self.spec, self.redactor)
        self.record.artifact("definition.json", self.spec.to_dict())
        self.record.artifact("target-assets.json", [a.to_dict() for a in self.spec.target.assets])
        self.record.artifact(
            "attack-assets.json", [a.to_dict() for a in self.spec.attack.assets] if self.spec.attack else []
        )
        self._state = dict(self.spec.attack.initial_state) if self.spec.attack else {}

    @property
    def closed(self):
        return self._closed

    @property
    def remaining_seconds(self):
        return max(0, self.deadline - self.clock())

    def _check(self, *, action=False):
        if self._closed:
            raise SessionStopped("Session is finished")
        if self._cancelled:
            raise SessionStopped("Session cancelled")
        if self.remaining_seconds <= 0:
            raise SessionStopped("Elapsed budget exhausted")
        if action and self.action_count >= self.spec.budgets.actions:
            raise SessionStopped("Action budget exhausted")
        if self.model_calls > self.spec.budgets.model_calls or self.model_cost > self.spec.budgets.model_cost:
            raise SessionStopped("Model budget exhausted")

    def _preconditions(self, phase):
        conditions = ()
        if self.spec.attack:
            conditions = self.spec.attack.preconditions
            if self.spec.attack.method:
                conditions += self.spec.attack.method.applicability
        outcomes = []
        for condition in conditions:
            if condition.phase != phase:
                continue
            if phase == "static":
                evidence = self.spec.target.to_dict()
            else:
                evidence = self._gateways["attack"].perform(self._resolve(condition.request))
            value = lookup(evidence, condition.path)
            status = "unknown" if value is MISSING else ("applicable" if value == condition.expected else "inapplicable")
            outcomes.append(status)
            self.record.event(
                "precondition", id=condition.id, phase=phase, status=status, observed=None if value is MISSING else value
            )
        if "inapplicable" in outcomes:
            self.result["applicability"] = "inapplicable"
            raise SessionStopped("Target prerequisite is unmet")
        if "unknown" in outcomes:
            self.result["applicability"] = "unknown"
            if self.spec.unknown_applicability == "stop":
                raise SessionStopped("Target prerequisite cannot be observed")
        elif self.result["applicability"] != "unknown" or phase == "static":
            self.result["applicability"] = "applicable"

    def initialize(self):
        require(not self._initialized, "Session already initialized")
        try:
            self._check()
            self.record.event("phase", phase="validate")
            self._preconditions("static")
            self._defense = self._defense or Gateway.from_environment("defense")
            self._gateways["defense"] = self._defense
            if self.spec.attack or self.spec.initiating_actor == "attack":
                self._attack = self._attack or Gateway.from_environment("attack")
                self._gateways["attack"] = self._attack
            for role, gateway in self._gateways.items():
                self.redactor.add(getattr(gateway, "_token", None))
                gateway.before_request = self._check
                gateway.record_event = lambda kind, _role=role, **data: self.record.event(kind, actor=_role, **data)
                self.identities[role] = gateway.identity()
            self._cleanup_gateways = dict(self._gateways)
            self._active_attack_identity = self.identities.get("attack")
            if "attack" in self.identities:
                require(
                    self.identities["attack"]["id"] != self.identities["defense"]["id"],
                    "Defense and attack must be distinct GitHub accounts",
                )
            source = self.spec.target.source_repository
            if source:
                owners = {identity["login"].lower() for identity in self.identities.values()}
                require(source.split("/")[0].lower() in owners, "Target source must belong to a verified machine account")
            references = set(self.spec.target.credential_refs.values())
            references |= {c.credential.environment for c in self.spec.provisioning.changes if c.credential}
            missing = sorted(name for name in references if not os.environ.get(name))
            if missing:
                self.result["applicability"] = "inapplicable"
                self.record.event("precondition", id="credential-references", status="inapplicable", missing=missing)
                raise SessionStopped("Missing target prerequisite: " + ", ".join(missing))
            for change in self.spec.provisioning.changes:
                if change.credential:
                    require(
                        bool(os.environ.get(change.credential.environment)),
                        f"Missing credential reference: {change.credential.environment}",
                    )
            self._verify_controller()
            self.record.event("phase", phase="resolve-source")
            self._resolve_source()
            self.record.manifest["actors"] = self.identities
            self.record.manifest["authority_boundary"] = {
                "scope": "All GitHub resources accessible to the dedicated machine-account credentials",
                "initial_capabilities": plain(self.spec.threat_model.initial_capabilities),
                "assumption": "Accounts and tokens have no grants to out-of-scope repositories",
                "acquired_authority": self.spec.threat_model.acquired_authority,
            }
            self.record.save_manifest()
            for role, gateway in self._gateways.items():
                self._check()
                self._initial_repositories[role] = gateway.owned_repositories()
            self.record.event("phase", phase="provision")
            self._provision()
            self.record.event("phase", phase="verify")
            self._preconditions("runtime")
            effective = self._defense.rest({"endpoint": f"/repos/{self.repository}"})
            self.record.artifact("effective-target.json", effective)
            self.record.manifest["effective_repository"] = self.repository
            self.record.manifest["reproduction_gaps"] = list(self.spec.provisioning.reproduction_gaps)
            self.record.manifest["reproduction_gaps"].append(
                "External GitHub action tags and hosted runner images may drift; "
                "consult the captured workflow and run evidence"
            )
            if source:
                self.record.manifest["reproduction_gaps"].append(
                    "Source repository settings, secrets and historical runs are not copied"
                )
            self.record.save_manifest()
            self._initialized = True
            self._task_started_at = datetime.now(timezone.utc).isoformat()
            self.result["execution"] = "running"
            self.record.event("phase", phase="session")
            self._perform(self.spec.task_trigger, self.spec.initiating_actor, check_preconditions=False)
            return self.observations()
        except Exception as exc:
            self._failure(exc)
            self._cleanup()
            self._closed = True
            self._save_result()
            raise

    def _verify_controller(self):
        if not self.spec.attack or not self.spec.attack.controller:
            return
        ref = self.spec.attack.controller
        path = Path(ref.path)
        if not path.is_absolute():
            path = self.workspace / path
        require(hashlib.sha256(path.read_bytes()).hexdigest() == ref.sha256, "Controller hash mismatch")
        self.record.snapshot("controller", path)
        from .worker import check_boundary

        check_boundary()

    def _resolve_source(self):
        target = self.spec.target
        self._source_entries = {}
        self._source_blobs = {}
        if not target.source_repository:
            return
        commit = self._defense.rest({"endpoint": f"/repos/{target.source_repository}/git/commits/{target.source_revision}"})
        if commit["status"] == 404:
            self.result["applicability"] = "inapplicable"
            raise SessionStopped("Immutable source revision is unavailable")
        ensure(commit["status"] == 200 and commit["body"]["sha"] == target.source_revision, "Source revision identity drift")
        self.record.artifact("source-commit.json", commit)
        endpoint = f"/repos/{target.source_repository}/git/trees/{commit['body']['tree']['sha']}"
        response = self._defense.rest({"endpoint": endpoint, "params": {"recursive": "1"}})
        ensure(response["status"] == 200 and not response["body"].get("truncated"), "Source tree unavailable or truncated")
        original = response["body"]
        self.record.artifact("source-tree.json", original)
        for item in original["tree"]:
            self._check()
            if item["type"] == "tree":
                continue
            if item["type"] == "blob":
                blob = self._defense.rest({"endpoint": f"/repos/{target.source_repository}/git/blobs/{item['sha']}"})
                ensure(blob["status"] == 200 and blob["body"]["sha"] == item["sha"], "Cannot retrieve original source asset")
                self._source_blobs[item["path"]] = blob["body"]
            self._source_entries[item["path"]] = {k: item[k] for k in ("path", "mode", "type", "sha")}
        self.record.artifact("source-assets.json", self._source_blobs)

    def _provision(self):
        login = self.identities["defense"]["login"]
        name = "gitinject-" + self.record.attempt_id[:16]
        response = self._defense.rest(
            {"method": "POST", "endpoint": "/user/repos", "json": {"name": name, "private": False, "auto_init": False}}
        )
        ensure(response["status"] == 201, f"Repository creation failed: HTTP {response['status']}")
        repo = response["body"]
        self.repository = repo["full_name"]
        ensure(self.repository.lower() == f"{login}/{name}".lower(), "Unexpected provisioned repository")
        self._track("defense", self.repository, repo["id"])
        tree_entries = dict(self._source_entries)
        blobs = self._source_blobs
        target = self.spec.target
        for asset in target.assets:
            tree_entries[asset.path] = {
                "path": asset.path,
                "mode": "100644",
                "type": "blob",
                "content": self._substitute(asset.content),
            }
        self.record.artifact("effective-assets.json", list(tree_entries.values()))
        ensure(bool(tree_entries), "Target must contain at least one baseline file")
        initial_paths = sorted(path for path, entry in tree_entries.items() if entry["type"] == "blob")
        ensure(bool(initial_paths), "GitHub requires a declared baseline blob to initialize a repository")
        first_path = min(initial_paths, key=lambda path: (path.startswith(".github/workflows/"), path))
        first = tree_entries[first_path]
        content = (
            base64.b64encode(first["content"].encode()).decode() if "content" in first else blobs[first_path]["content"]
        )
        initial = self._defense.rest(
            {
                "method": "PUT",
                "endpoint": f"/repos/{self.repository}/contents/{first_path}",
                "json": {"message": "initialize declared baseline", "branch": "main", "content": content},
            }
        )
        ensure(initial["status"] == 201, "Baseline initialization failed")
        for path, blob in blobs.items():
            self._check()
            copied = self._defense.rest(
                {
                    "method": "POST",
                    "endpoint": f"/repos/{self.repository}/git/blobs",
                    "json": {"encoding": "base64", "content": blob["content"]},
                }
            )
            ensure(copied["status"] == 201 and copied["body"]["sha"] == blob["sha"], "Source blob identity drift")
        tree = self._defense.rest(
            {
                "method": "POST",
                "endpoint": f"/repos/{self.repository}/git/trees",
                "json": {"tree": list(tree_entries.values())},
            }
        )
        ensure(tree["status"] == 201, "Baseline tree creation failed")
        commit = self._defense.rest(
            {
                "method": "POST",
                "endpoint": f"/repos/{self.repository}/git/commits",
                "json": {
                    "message": "declared target baseline",
                    "tree": tree["body"]["sha"],
                    "parents": [initial["body"]["commit"]["sha"]],
                },
            }
        )
        ensure(commit["status"] == 201, "Baseline commit creation failed")
        ref = self._defense.rest(
            {
                "method": "PATCH",
                "endpoint": f"/repos/{self.repository}/git/refs/heads/main",
                "json": {"sha": commit["body"]["sha"], "force": False},
            }
        )
        ensure(ref["status"] == 200, "Baseline ref creation failed")
        self.record.manifest["baseline_commit"] = commit["body"]["sha"]
        for change in self.spec.provisioning.changes:
            self._check()
            config = self._substitute(plain(change.configuration))
            self.record.event(
                "provisioning_change",
                id=change.id,
                reason=change.reason,
                transformation_kind=change.kind,
                requested=config,
                credential_reference=plain(change.credential),
            )
            if change.kind == "secret":
                self._defense.install_secret(self.repository, config["name"], os.environ[change.credential.environment])
                observed = {"installed": True, "name": config["name"], "value": "not observable"}
            elif change.kind == "variable":
                observed = self._defense.rest(
                    {"method": "POST", "endpoint": f"/repos/{self.repository}/actions/variables", "json": config}
                )
                ensure(observed["status"] == 201, "Variable installation failed")
            else:
                observed = self._defense.rest(config)
                ensure(200 <= observed["status"] < 300, "Declared provisioning transformation failed")
            self.record.event("provisioning_effect", id=change.id, observed=observed)
        self.record.save_manifest()

    def _substitute(self, value, *, private=False):
        if isinstance(value, str):
            context = {
                "repository": self.repository,
                "defense_login": self.identities.get("defense", {}).get("login"),
                "attack_login": self.identities.get("attack", {}).get("login"),
            }

            def binding(key):
                if key in context and context[key] is not None:
                    return context[key]
                if key.startswith("binding.") and self.spec.attack:
                    values = dict(self.spec.attack.method.parameters) if self.spec.attack.method else {}
                    values.update(self.spec.attack.bindings)
                    bound = lookup(values, key[len("binding.") :])
                    if bound is not MISSING:
                        return plain(bound)
                if key.startswith("response."):
                    observed = lookup(
                        {k: v for k, v in self._responses.items() if private or self._response_roles.get(k) == "attack"},
                        key[len("response.") :],
                    )
                    if observed is not MISSING:
                        return observed
                raise PolicyError(f"Unresolved binding: {key}")

            pattern = r"\$\{([^{}]+)\}"
            exact = re.fullmatch(pattern, value)
            if exact:
                return binding(exact.group(1))
            return re.sub(pattern, lambda match: str(binding(match.group(1))), value)
        if isinstance(value, dict):
            return {key: self._substitute(item, private=private) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [self._substitute(item, private=private) for item in value]
        return value

    def _resolve(self, action, *, private=False):
        return Action.from_dict(self._substitute(action.to_dict(), private=private))

    def act(self, action):
        require(self.spec.attack is not None and self._initialized, "Attack session is not initialized")
        if "github" not in self.spec.threat_model.initial_capabilities:
            raise PolicyError("Threat model does not grant GitHub actions")
        action = action if isinstance(action, Action) else Action.from_dict(action)
        if action.wait_for:
            data = action.to_dict()
            options = data.pop("wait_for")
            request = Action.from_dict(data)
            response = self.wait(request, **options)
            self._responses[action.id] = response
            self._response_roles[action.id] = "attack"
            self.record.event("wait_complete", actor="attack", action=action.to_dict(), response=response)
            return response
        response = self._perform(action, "attack")
        return response if "github" in self.spec.threat_model.observations else {"recorded": True}

    def _perform(self, action, role, *, check_preconditions=True):
        self._check(action=True)
        if not isinstance(action, Action):
            action = Action.from_dict(action)
        if action.id in self._responses:
            raise PolicyError("Action ID already used; mutations are never retried automatically")
        if not set(action.depends_on) <= self._responses.keys():
            raise PolicyError("Missing action dependencies")
        if check_preconditions:
            self._preconditions("dynamic")
        resolved = self._resolve(action, private=role == "defense")
        self.action_count += 1
        self.record.event(
            "action_planned",
            actor=role,
            action=action.to_dict(),
            resolved=resolved.to_dict(),
            authorization="GitHub account permissions",
            decision="requested",
        )
        gateway = self._gateways[role]
        gateway.timeout = max(0.1, min(30, self.remaining_seconds))
        try:
            response = gateway.perform(resolved)
        except PolicyError as exc:
            self.record.event("policy_decision", actor=role, action_id=action.id, decision="rejected", reason=str(exc))
            raise
        except AmbiguousOperation:
            self._responses[action.id] = {"status": None, "uncertain": True}
            self.record.event("action_receipt", actor=role, action_id=action.id, uncertain=True)
            raise
        self._responses[action.id] = response
        self._response_roles[action.id] = role
        self._subjects[action.id] = resolved.subject
        self.record.event(
            "action_receipt",
            actor=role,
            principal=self._active_attack_identity if role == "attack" else self.identities[role],
            action_id=action.id,
            response=response,
            subject=resolved.subject,
            commit_sha=response.get("commit_sha"),
        )
        self._detect_resources(role, response)
        return self.redactor(response)

    def _detect_resources(self, role, response):
        def visit(value):
            if isinstance(value, dict):
                if type(value.get("id")) is int and isinstance(value.get("full_name"), str):
                    name = value["full_name"]
                    owner = name.split("/")[0].lower()
                    for cleanup_role, identity in self.identities.items():
                        if owner == identity["login"].lower() and value["id"] not in self._initial_repositories.get(
                            cleanup_role, {}
                        ):
                            self._track(cleanup_role, name, value["id"])
                for item in value.values():
                    visit(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    visit(item)

        visit(response)

    def _track(self, role, name, identity):
        key = (role, identity)
        if key not in self._resources:
            self._resources[key] = name
            self.record.event("resource", actor=role, name=name, id=identity, state="created")

    def observations(self):
        self._check()
        value = {
            "repository": self.repository,
            "actors": self.identities,
            "remaining_seconds": self.remaining_seconds,
            "remaining_actions": self.spec.budgets.actions - self.action_count,
            "state": self._state,
            "seed": self.spec.seed,
            "bindings": plain(self.spec.attack.bindings) if self.spec.attack else {},
            "controller_configuration": plain(self.spec.attack.controller.configuration)
            if self.spec.attack and self.spec.attack.controller
            else {},
        }
        if "github" in self.spec.threat_model.observations and self.spec.threat_model.adaptation == "online":
            value["responses"] = {k: v for k, v in self._responses.items() if self._response_roles.get(k) == "attack"}
        self.record.event("observation", observation=value)
        return self.redactor(value)

    def _pause(self, seconds):
        deadline = min(self.deadline, self.clock() + seconds)
        while self.clock() < deadline:
            self._check()
            time.sleep(min(0.5, max(0, deadline - self.clock())))

    def wait(self, request, *, until_path="body.status", expected="completed", timeout=60, poll_seconds=2):
        require("github" in self.spec.threat_model.observations, "GitHub observations not permitted")
        request = request if isinstance(request, Action) else Action.from_dict(request)
        require(
            request.transport == "rest" and request.parameters.get("method", "GET").upper() == "GET",
            "Wait requests must be read-only",
        )
        require(timeout > 0 and poll_seconds > 0, "Invalid wait duration")
        deadline = min(self.deadline, self.clock() + timeout)
        last = None
        counter = 0
        while self.clock() < deadline:
            self._check()
            data = request.to_dict()
            data["id"] = f"{request.id}-poll-{counter}"
            data["wait_for"] = {}
            counter += 1
            last = self.act(Action.from_dict(data))
            if lookup(last, until_path) == expected:
                return last
            self._pause(min(poll_seconds, max(0, deadline - self.clock())))
        self._check()
        return {"timed_out": True, "last_response": last}

    def checkpoint(self, state, *, model_calls=0, model_cost=0, payloads=None, simulated=False):
        self._check()
        require(type(model_calls) is int and model_calls >= 0 and model_cost >= 0, "Invalid model accounting")
        if simulated:
            require("offline" in self.spec.threat_model.initial_capabilities, "Offline generation not permitted")
        self.model_calls += model_calls
        self.model_cost += model_cost
        self._check()
        self._state = json.loads(canonical(state))
        checkpoint_id = uuid.uuid4().hex
        value = {
            "id": checkpoint_id,
            "state": state,
            "payloads": payloads,
            "simulated": simulated,
            "model_calls": self.model_calls,
            "model_cost": self.model_cost,
            "experiment_revision": self.spec.revision,
            "evaluation_revision": self.spec.evaluation.revision,
        }
        self.record.artifact(f"checkpoints/{checkpoint_id}.json", value)
        self.record.event("checkpoint", **value)
        return checkpoint_id

    def cancel(self, reason="cancelled by controller"):
        self._cancelled = True
        self.record.event("cancellation", reason=reason)

    def record_escalation(self, evidence):
        self.record.event("authority_escalation", evidence=evidence, usage="record-only", actor="attack")

    def use_acquired_authority(self, response_path):
        self._check(action=True)
        if self.spec.threat_model.acquired_authority != "observed-machine-account":
            raise PolicyError("Threat model does not permit using acquired authority")
        response_id = response_path.split(".", 1)[0]
        if self._response_roles.get(response_id) != "attack":
            raise PolicyError("Acquired authority must originate in an observed attack response")
        token = lookup(self._responses, response_path)
        if not isinstance(token, str) or not token or token in {"[REDACTED]"}:
            raise PolicyError("Acquired token is unavailable")
        self.redactor.add(token)
        gateway = Gateway(token, "attack", timeout=min(30, self.remaining_seconds))
        identity = gateway.identity()
        if identity["id"] not in {i["id"] for i in self.identities.values()}:
            raise PolicyError("Acquired authority belongs to an out-of-scope account")
        self.action_count += 1
        self._active_attack_identity = identity
        gateway.record_event = lambda kind, **data: self.record.event(kind, actor="attack", principal=identity, **data)
        self._gateways["attack"] = gateway
        self.record.event(
            "authority_acquired",
            source=response_path,
            principal=identity,
            credential_fingerprint=hashlib.sha256(token.encode()).hexdigest(),
            attribution="authority observed through target; no credential was provisioned",
        )
        return {"principal": identity, "source": response_path}

    def _collect_invocation(self, evidence):
        config = self._substitute(plain(self.spec.execution.get("invocation")))
        if not config:
            return None
        require(set(config) <= {"workflow_path", "job_name", "step_name", "actor_login"}, "Invalid invocation configuration")
        require(
            all(config.get(k) for k in ("workflow_path", "job_name", "step_name")),
            "Invocation requires workflow, job and step",
        )
        runs = self._defense.rest({"endpoint": f"/repos/{self.repository}/actions/runs", "params": {"per_page": 100}})
        evidence["workflow_runs"] = runs
        if runs["status"] != 200:
            return None
        expected_events = Counter(
            subject.get("event")
            for action_id, subject in self._subjects.items()
            if subject.get("event") and 200 <= self._responses[action_id].get("status", 0) < 300
        )
        verified_events = Counter()
        verified = False
        pending = False
        receipts = []
        for run in runs["body"].get("workflow_runs", []):
            created_at = run.get("created_at")
            if not created_at:
                continue
            started = datetime.fromisoformat(self._task_started_at).replace(microsecond=0)
            if datetime.fromisoformat(created_at.replace("Z", "+00:00")) < started:
                continue
            if run.get("path", "").split("@")[0] != config["workflow_path"]:
                continue
            if run.get("status") != "completed":
                pending = True
                continue
            jobs = self._defense.rest({"endpoint": f"/repos/{self.repository}/actions/runs/{run['id']}/jobs"})
            associated = []
            for action_id, response in self._responses.items():
                subject = response.get("body", {})
                if isinstance(subject, dict):
                    if subject.get("head", {}).get("sha") == run.get("head_sha"):
                        associated.append(action_id)
                    number = subject.get("number")
                    if number and any(pr.get("number") == number for pr in run.get("pull_requests", [])):
                        associated.append(action_id)
                if response.get("commit_sha") == run.get("head_sha"):
                    associated.append(action_id)
            invoked = False
            if jobs["status"] == 200:
                for job in jobs["body"].get("jobs", []):
                    if job.get("name") == config["job_name"]:
                        for step in job.get("steps", []):
                            if step.get("name") == config["step_name"] and step.get("conclusion") == "success":
                                invoked = True
            if config.get("actor_login") and run.get("actor", {}).get("login") != config["actor_login"]:
                invoked = False
            receipt = {
                "run_id": run["id"],
                "head_sha": run.get("head_sha"),
                "event": run.get("event"),
                "action_ids": sorted(set(associated)),
                "agent_invoked": invoked,
                "run_actor": run.get("actor"),
                "jobs": jobs,
            }
            receipts.append(receipt)
            self.record.event("workflow_receipt", **receipt)
            verified |= invoked
            if invoked:
                verified_events[run.get("event")] += 1
        evidence["invocation_receipts"] = receipts
        complete = all(verified_events[event] >= count for event, count in expected_events.items())
        return True if verified and complete and not pending else None

    def finish(self):
        require(not self._closed, "Session already finished")
        evidence = {"responses": self._responses, "actors": self.identities}
        try:
            self._check()
            require(self._initialized, "Session is not initialized")
            self.record.event("phase", phase="collect")
            wait_deadline = min(self.deadline, self.clock() + self.spec.execution.get("wait_seconds", 30))
            self.invocation = self._collect_invocation(evidence)
            while self.spec.execution.get("invocation") and self.invocation is not True and self.clock() < wait_deadline:
                self._check()
                self._pause(min(self.spec.execution.get("poll_seconds", 2), max(0, wait_deadline - self.clock())))
                self.invocation = self._collect_invocation(evidence)
            for request in self.spec.evaluation.evidence_requests:
                self._check()
                evidence[request.id] = self._defense.perform(self._resolve(request, private=True))
            self.result["invocation"] = self.invocation
            self._check()
            self.record.event("phase", phase="evaluate")
            try:
                self.result.update(evaluate(self.spec.evaluation, evidence, self.invocation))
            except Exception as exc:
                self.result.update(evaluation="error", evaluation_error=str(exc))
            self.result["execution"] = "completed"
        except Exception as exc:
            self._failure(exc)
        finally:
            self.record.artifact("evidence.json", evidence)
            self._cleanup()
            self._closed = True
            self._save_result()
        return self.redactor(self.result)

    def _failure(self, exc):
        if isinstance(exc, PolicyError) or isinstance(exc, ValueError):
            status = "policy_failure"
        elif isinstance(exc, SessionStopped):
            status = "cancelled" if self._cancelled else "stopped"
        else:
            status = "error"
        self.result.update(execution=status, execution_error=str(exc))
        self.record.event("failure", category=status, error=str(exc))

    def _cleanup(self):
        self.record.event("phase", phase="cleanup")
        for gateway in self._cleanup_gateways.values():
            gateway.before_request = None
            gateway.timeout = 30
        errors = []
        for role, baseline in self._initial_repositories.items():
            try:
                current = self._cleanup_gateways[role].owned_repositories()
                for identity, name in current.items():
                    if identity not in baseline and (role, identity) not in self._resources:
                        self.record.event(
                            "resource_unattributed", actor=role, name=name, id=identity, state="requires-reconciliation"
                        )
                        errors.append(f"Unattributed repository retained: {name} ({identity})")
            except Exception as exc:
                errors.append(f"Resource reconciliation for {role}: {exc}")
        if self.spec.cleanup:
            for (role, identity), name in list(self._resources.items())[::-1]:
                try:
                    self._cleanup_gateways[role].delete_repository(name, identity)
                    self.record.event(
                        "resource", actor=role, id=identity, name=name, state="deleted", cleanup_role="privileged-host"
                    )
                    del self._resources[(role, identity)]
                except Exception as exc:
                    errors.append(str(exc))
        if errors:
            self.result["cleanup_errors"] = errors
        self.record.manifest["remaining_resources"] = [
            {"actor": role, "id": identity, "name": name} for (role, identity), name in self._resources.items()
        ]
        self.record.save_manifest()

    def _save_result(self):
        self.result.update(
            attempt_id=self.record.attempt_id,
            actions=self.action_count,
            model_calls=self.model_calls,
            model_cost=self.model_cost,
            model_accounting={
                "reported_controller_calls": self.model_calls,
                "reported_controller_cost": self.model_cost,
                "target_model_calls": None,
                "target_model_cost": None,
            },
        )
        self.record.artifact("result.json", self.result)
        self.record.event("phase", phase="finished", result=self.result)

    def run(self):
        try:
            self.initialize()
            if self.spec.attack:
                if self.spec.attack.controller:
                    from .worker import run_controller

                    run_controller(self)
                else:
                    for action in self.spec.attack.actions:
                        self.act(action)
            return self.finish()
        except BaseException as exc:
            if not self._closed:
                self._failure(exc)
                self.record.artifact("partial-evidence.json", {"responses": self._responses})
                self._cleanup()
                self._closed = True
                self._save_result()
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            return self.redactor(self.result)
