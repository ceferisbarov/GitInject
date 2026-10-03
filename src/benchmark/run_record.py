"""Local attempt manifests and append-only execution journals."""

import hashlib
import json
import os
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class RunSpec:
    workflow: str
    scenario: str
    parameters: dict = field(default_factory=dict)
    seed: int | None = None
    parent_attempt_id: str | None = None
    attack: str | None = None
    cleanup: bool = True
    unaligned: bool | str = False

    def __post_init__(self):
        if not isinstance(self.parameters, dict):
            raise ValueError("Scenario parameters must be a JSON object")
        if self.seed is not None and type(self.seed) is not int:
            raise ValueError("Scenario seed must be an integer")


def write_json(path: Path, value) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


class RunRecord:
    def __init__(self, workspace_dir: str, spec: RunSpec):
        self.attempt_id = uuid.uuid4().hex
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.directory = Path(workspace_dir) / "runs" / self.attempt_id
        self.directory.mkdir(parents=True)
        self.manifest = {
            "schema_version": 1,
            "attempt_id": self.attempt_id,
            "timestamp": self.timestamp,
            "spec": asdict(spec),
            "inputs": {},
        }
        try:
            revision = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=workspace_dir,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            self.manifest["source_revision"] = revision
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=workspace_dir,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            self.manifest["source_dirty"] = bool(status.strip())
        except (OSError, subprocess.CalledProcessError):
            self.manifest["source_revision"] = None
        self.save_manifest()
        self.event("phase", phase="created")

    def save_manifest(self) -> None:
        write_json(self.directory / "manifest.json", self.manifest)

    def event(self, kind: str, **data) -> None:
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "kind": kind, **data}
        with (self.directory / "events.jsonl").open("a") as handle:
            handle.write(json.dumps(entry, allow_nan=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def snapshot(self, label: str, source: str | Path, *, prefix: str = "") -> None:
        source = Path(source)
        files = sorted(source.rglob("*")) if source.is_dir() else [source]
        hashes = dict(self.manifest["inputs"].get(label, {}))
        for path in files:
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            relative = path.relative_to(source) if source.is_dir() else Path(path.name)
            relative = Path(prefix) / relative
            content = path.read_bytes()
            destination = self.directory / "inputs" / label / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            hashes[str(relative)] = hashlib.sha256(content).hexdigest()
        self.manifest["inputs"][label] = hashes
        self.save_manifest()

    def artifact(self, name: str, value) -> Path:
        root = self.directory / "artifacts"
        path = root / name
        if path.resolve() == root.resolve() or root.resolve() not in path.resolve().parents:
            raise ValueError("Artifact path must stay inside the attempt")
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json(path, value)
        self.event(
            "artifact",
            path=str(path.relative_to(self.directory)),
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        return path
