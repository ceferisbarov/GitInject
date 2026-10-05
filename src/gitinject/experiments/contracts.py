"""Versioned experiment definitions. Runtime state and credentials live elsewhere."""

import hashlib
import json
import re
from dataclasses import dataclass, field, fields
from types import UnionType
from typing import ClassVar, get_args, get_origin, get_type_hints


def canonical(value):
    return json.dumps(plain(value), sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def plain(value):
    if isinstance(value, Contract):
        return {f.name: plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, dict):
        return {key: plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    return value


def validate_type(value, annotation, name):
    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is UnionType:
        for kind in arguments:
            try:
                validate_type(value, kind, name)
                return
            except ValueError:
                pass
        raise ValueError(f"Invalid type for {name}")
    if origin is tuple:
        require(isinstance(value, tuple), f"{name} must be an array")
        for item in value:
            validate_type(item, arguments[0], name)
    elif annotation is dict:
        require(isinstance(value, dict), f"{name} must be an object")
    elif annotation is float:
        require(type(value) in {int, float}, f"{name} must be numeric")
    elif annotation in {str, int, bool, type(None)}:
        require(type(value) is annotation, f"Invalid type for {name}")
    elif annotation is not object:
        require(isinstance(value, annotation), f"Invalid type for {name}")


class FrozenDict(dict):
    def _immutable(self, *args, **kwargs):
        raise TypeError("Experiment definitions are immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _immutable


def freeze(value):
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        return FrozenDict({key: freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    return value


def require(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True, kw_only=True)
class Contract:
    schema_version: int = 1
    nested: ClassVar[dict] = {}

    def __post_init__(self):
        require(type(self.schema_version) is int and self.schema_version == 1, "Unsupported schema version")
        for f in fields(self):
            object.__setattr__(self, f.name, freeze(getattr(self, f.name)))
        annotations = get_type_hints(type(self))
        for f in fields(self):
            validate_type(getattr(self, f.name), annotations[f.name], f.name)
        for key, kind in self.nested.items():
            value = getattr(self, key)
            if value is not None:
                if isinstance(kind, tuple):
                    require(isinstance(value, tuple) and all(isinstance(v, kind[0]) for v in value), f"Invalid {key}")
                else:
                    require(isinstance(value, kind), f"Invalid {key}")
        canonical(self)
        self.validate()

    def validate(self):
        pass

    def to_dict(self):
        return plain(self)

    @property
    def revision(self):
        return digest(self)

    @classmethod
    def from_dict(cls, value):
        require(isinstance(value, dict), f"{cls.__name__} must be an object")
        unknown = set(value) - {f.name for f in fields(cls)}
        require(not unknown, f"Unknown {cls.__name__} fields: {sorted(unknown)}")
        data = dict(value)
        for key, kind in cls.nested.items():
            if key in data and data[key] is not None:
                if isinstance(kind, tuple):
                    require(isinstance(data[key], (list, tuple)), f"{key} must be an array")
                    data[key] = tuple(kind[0].from_dict(item) for item in data[key])
                else:
                    data[key] = kind.from_dict(data[key])
        try:
            return cls(**data)
        except TypeError as exc:
            raise ValueError(f"Invalid {cls.__name__}: {exc}") from exc


@dataclass(frozen=True, kw_only=True)
class CredentialRef(Contract):
    environment: str

    def validate(self):
        require(bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", self.environment)), "Credential must be an environment reference")


@dataclass(frozen=True, kw_only=True)
class Asset(Contract):
    path: str
    content: str

    def validate(self):
        require(isinstance(self.content, str), "Asset content must be text")
        require(
            isinstance(self.path, str)
            and self.path
            and not self.path.startswith("/")
            and ".." not in self.path.split("/")
            and ".git" not in self.path.split("/"),
            "Unsafe asset path",
        )


@dataclass(frozen=True, kw_only=True)
class TargetSpec(Contract):
    id: str
    source_repository: str | None = None
    source_revision: str | None = None
    assets: tuple[Asset, ...] = ()
    agent: dict = field(default_factory=dict)
    permissions: dict = field(default_factory=dict)
    runner_environment: dict = field(default_factory=dict)
    baseline: dict = field(default_factory=dict)
    credential_refs: dict = field(default_factory=dict)
    nested: ClassVar = {"assets": (Asset,)}

    def validate(self):
        require(bool(self.id), "Target requires an identity")
        require(
            (self.source_repository is None) == (self.source_revision is None),
            "Source repository and revision required together",
        )
        if self.source_repository:
            require(bool(re.fullmatch(r"[\w.-]+/[\w.-]+", self.source_repository)), "Invalid source repository")
            require(
                bool(re.fullmatch(r"[0-9a-f]{40}", self.source_revision)), "Target source must be an immutable commit SHA"
            )
        require(bool(self.source_repository or self.assets), "Target requires source assets or baseline files")
        require(len({a.path for a in self.assets}) == len(self.assets), "Duplicate target asset path")
        require(
            all(isinstance(v, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", v) for v in self.credential_refs.values()),
            "Target credentials must be environment references",
        )


@dataclass(frozen=True, kw_only=True)
class Action(Contract):
    id: str
    transport: str = "rest"
    parameters: dict = field(default_factory=dict)
    depends_on: tuple[str, ...] = ()
    subject: dict = field(default_factory=dict)
    wait_for: dict = field(default_factory=dict)

    def validate(self):
        require(bool(self.id), "Action requires an identity")
        require(self.transport in {"rest", "graphql", "gh", "git"}, "Unsupported transport")
        require(
            isinstance(self.parameters, dict) and isinstance(self.subject, dict),
            "Action parameters and subject must be objects",
        )
        if self.wait_for:
            require(
                self.transport == "rest" and self.parameters.get("method", "GET").upper() == "GET",
                "Wait actions must be read-only",
            )
            require(
                not set(self.wait_for) - {"until_path", "expected", "timeout", "poll_seconds"}, "Unsupported wait options"
            )
        require(all(isinstance(v, str) for v in self.depends_on), "Invalid action dependencies")


@dataclass(frozen=True, kw_only=True)
class ProvisioningChange(Contract):
    id: str
    reason: str
    kind: str
    configuration: dict = field(default_factory=dict)
    credential: CredentialRef | None = None
    nested: ClassVar = {"credential": CredentialRef}

    def validate(self):
        require(bool(self.id) and bool(self.reason), "Provisioning changes require identity and reason")
        require(self.kind in {"rest", "secret", "variable"}, "Unsupported privileged transformation")
        require(self.kind != "secret" or self.credential is not None, "Secret installation requires a credential reference")


@dataclass(frozen=True, kw_only=True)
class ProvisioningSpec(Contract):
    changes: tuple[ProvisioningChange, ...] = ()
    reproduction_gaps: tuple[str, ...] = ()
    nested: ClassVar = {"changes": (ProvisioningChange,)}

    def validate(self):
        require(len({v.id for v in self.changes}) == len(self.changes), "Duplicate provisioning change")


@dataclass(frozen=True, kw_only=True)
class ThreatModel(Contract):
    id: str
    scope: str = "machine-account-permissions"
    initial_capabilities: tuple[str, ...] = ("github",)
    observations: tuple[str, ...] = ("github",)
    adaptation: str = "static"
    constraints: dict = field(default_factory=dict)
    acquired_authority: str = "record-only"

    def validate(self):
        require(bool(self.id), "Threat model requires an identity")
        require(self.scope == "machine-account-permissions", "Only platform-enforced machine-account scope is supported")
        require(not self.constraints, "Arbitrary API constraints cannot be soundly enforced; use GitHub account permissions")
        require(set(self.initial_capabilities) <= {"github", "offline"}, "Unsupported capability")
        require(set(self.observations) <= {"github", "offline"}, "Private evaluator observations are unavailable")
        require(self.adaptation in {"static", "offline", "online"}, "Unsupported adaptation mode")
        require(
            self.acquired_authority in {"record-only", "observed-machine-account"}, "Unsupported acquired-authority policy"
        )


@dataclass(frozen=True, kw_only=True)
class ControllerRef(Contract):
    path: str
    sha256: str
    configuration: dict = field(default_factory=dict)

    def validate(self):
        require(
            bool(self.path) and bool(re.fullmatch(r"[0-9a-f]{64}", self.sha256)), "Controller requires a path and SHA256"
        )


@dataclass(frozen=True, kw_only=True)
class Precondition(Contract):
    id: str
    phase: str
    path: str
    expected: object = True
    request: Action | None = None
    nested: ClassVar = {"request": Action}

    def validate(self):
        require(bool(self.id) and bool(self.path), "Precondition requires identity and evidence path")
        require(self.phase in {"static", "runtime", "dynamic"}, "Invalid precondition phase")
        if self.phase != "static":
            require(
                self.request is not None
                and self.request.transport == "rest"
                and self.request.parameters.get("method", "GET").upper() == "GET",
                "Runtime preconditions require a read-only REST request",
            )


@dataclass(frozen=True, kw_only=True)
class AttackMethod(Contract):
    id: str
    implementation: str
    trust_boundary: str
    intended_outcome: str
    parameters: dict = field(default_factory=dict)
    applicability: tuple[Precondition, ...] = ()
    nested: ClassVar = {"applicability": (Precondition,)}

    def validate(self):
        require(all((self.id, self.implementation, self.trust_boundary, self.intended_outcome)), "Incomplete attack method")


@dataclass(frozen=True, kw_only=True)
class AttackInstance(Contract):
    id: str
    method: AttackMethod | None = None
    bindings: dict = field(default_factory=dict)
    assets: tuple[Asset, ...] = ()
    initial_state: dict = field(default_factory=dict)
    preconditions: tuple[Precondition, ...] = ()
    actions: tuple[Action, ...] = ()
    controller: ControllerRef | None = None
    parent_candidate: str | None = None
    intended_outcome: str = ""
    nested: ClassVar = {
        "method": AttackMethod,
        "assets": (Asset,),
        "preconditions": (Precondition,),
        "actions": (Action,),
        "controller": ControllerRef,
    }

    def validate(self):
        require(bool(self.id), "Attack instance requires an identity")
        require(not (self.actions and self.controller), "Select a sequence or a controller")
        require(len({a.id for a in self.actions}) == len(self.actions), "Duplicate action identity")
        seen = set()
        for action in self.actions:
            require(set(action.depends_on) <= seen, "Action dependency must reference an earlier action")
            seen.add(action.id)


@dataclass(frozen=True, kw_only=True)
class EvaluationContract(Contract):
    id: str
    implementation: str = "checks-v1"
    version: str = "1"
    checks: tuple[dict, ...] = ()
    configuration: dict = field(default_factory=dict)
    evidence_requests: tuple[Action, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    parent_revision: str | None = None
    nested: ClassVar = {"evidence_requests": (Action,)}

    def validate(self):
        require(
            bool(self.id) and self.implementation == "checks-v1" and self.version == "1",
            "Unsupported evaluator implementation/version",
        )
        for check in self.checks:
            require(
                check.get("dimension") in {"utility", "security"} and bool(check.get("path")), "Invalid evaluation check"
            )
            require(isinstance(check["path"], str), "Evaluation evidence path must be text")
            require(
                check.get("operation", "equals") in {"equals", "contains", "text_contains", "contains_secret", "exists"},
                "Unsupported evaluation check operation",
            )
            require(type(check.get("requires_invocation", True)) is bool, "Invalid invocation requirement")
            if check.get("operation") in {"contains", "text_contains"}:
                require("expected" in check, "Containment checks require an expected value")
            if check.get("operation") == "contains_secret":
                require(
                    isinstance(check.get("credential_environment"), str)
                    and re.fullmatch(r"[A-Z][A-Z0-9_]*", check["credential_environment"]),
                    "Secret checks require a credential reference",
                )
        require(
            len({a.id for a in self.evidence_requests}) == len(self.evidence_requests),
            "Duplicate evaluator evidence identity",
        )
        for action in self.evidence_requests:
            require(
                action.transport == "rest" and action.parameters.get("method", "GET").upper() == "GET",
                "Evaluator evidence requests must be read-only REST",
            )


@dataclass(frozen=True, kw_only=True)
class Budgets(Contract):
    elapsed_seconds: float = 300
    actions: int = 100
    model_calls: int = 0
    model_cost: float = 0
    trials: int = 1

    def validate(self):
        require(
            isinstance(self.elapsed_seconds, (int, float)) and self.elapsed_seconds > 0, "Positive elapsed budget required"
        )
        for key in ("actions", "model_calls", "trials"):
            value = getattr(self, key)
            require(type(value) is int and value >= 0, f"Invalid {key} budget")
        require(self.trials > 0 and self.model_cost >= 0, "Invalid trial/cost budget")


@dataclass(frozen=True, kw_only=True)
class ExperimentSpec(Contract):
    id: str
    target: TargetSpec
    threat_model: ThreatModel
    evaluation: EvaluationContract
    legitimate_task: str
    task_trigger: Action
    initiating_actor: str = "defense"
    attack: AttackInstance | None = None
    provisioning: ProvisioningSpec = field(default_factory=ProvisioningSpec)
    budgets: Budgets = field(default_factory=Budgets)
    seed: int = 0
    cleanup: bool = True
    unknown_applicability: str = "stop"
    execution: dict = field(default_factory=dict)
    parent_attempt: str | None = None
    parent_checkpoint: str | None = None
    nested: ClassVar = {
        "target": TargetSpec,
        "threat_model": ThreatModel,
        "evaluation": EvaluationContract,
        "task_trigger": Action,
        "attack": AttackInstance,
        "provisioning": ProvisioningSpec,
        "budgets": Budgets,
    }

    def validate(self):
        require(bool(self.id) and bool(self.legitimate_task), "Experiment requires identity and legitimate task")
        require(self.initiating_actor in {"defense", "attack"}, "Invalid initiating actor")
        require(
            self.attack is not None or self.initiating_actor == "defense",
            "Benign experiment must use defense initiating actor",
        )
        require(type(self.seed) is int and type(self.cleanup) is bool, "Invalid seed/cleanup")
        require(self.unknown_applicability in {"stop", "continue"}, "Invalid unknown applicability policy")
        if self.attack and self.attack.controller:
            require(
                self.threat_model.adaptation != "static",
                "Static attacks use action sequences; controllers declare offline/online adaptation",
            )
        require(
            isinstance(self.execution.get("wait_seconds", 30), (int, float)) and self.execution.get("wait_seconds", 30) >= 0,
            "Invalid workflow wait budget",
        )
        poll_seconds = self.execution.get("poll_seconds", 2)
        require(type(poll_seconds) in {int, float} and poll_seconds > 0, "Invalid polling interval")
        if self.execution.get("invocation"):
            invocation = self.execution["invocation"]
            require(
                isinstance(invocation, dict)
                and not set(invocation) - {"workflow_path", "job_name", "step_name", "actor_login"},
                "Invalid invocation configuration",
            )
            require(
                all(invocation.get(k) for k in ("workflow_path", "job_name", "step_name")),
                "Invocation requires workflow, job and step",
            )
        require(
            not set(self.execution) - {"invocation", "poll_seconds", "wait_seconds"},
            "Live reuse/reset is unsupported; trials always use fresh repositories",
        )


def load_spec(path):
    from pathlib import Path

    return ExperimentSpec.from_dict(json.loads(Path(path).read_text()))
