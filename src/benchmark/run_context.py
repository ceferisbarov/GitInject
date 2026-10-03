"""The runtime capabilities supplied to Python scenarios."""

import random
from dataclasses import dataclass, field
from typing import Callable, Literal

from github import GithubException

from .run_record import RunRecord, RunSpec
from .utils.gh_client import GitHubClient


@dataclass(frozen=True)
class TriggerReceipt:
    event_type: str | None = None
    subject_kind: Literal["pr", "issue"] | None = None
    subject_number: int | None = None
    workflow_run_id: int | None = None

    def __post_init__(self):
        if self.subject_kind not in {None, "pr", "issue"}:
            raise ValueError("Subject kind must be pr or issue")
        if (self.subject_kind is None) != (self.subject_number is None):
            raise ValueError("Subject kind and number must be supplied together")
        for value in (self.subject_number, self.workflow_run_id):
            if value is not None and (type(value) is not int or value <= 0):
                raise ValueError("GitHub identifiers must be positive integers")


@dataclass
class RunContext:
    spec: RunSpec
    record: RunRecord
    state: dict
    actors: dict[str, GitHubClient]
    default_trigger: Callable[[], TriggerReceipt]
    collect_target: Callable[[], dict]
    _repositories: list[tuple[str, str, int]] = field(default_factory=list)

    def __post_init__(self):
        self.rng = random.Random(self.spec.seed)

    @property
    def parameters(self) -> dict:
        return self.spec.parameters

    def github(self, actor: str) -> GitHubClient:
        if actor not in self.actors:
            raise ValueError(f"Required GitHub actor is unavailable: {actor}")
        return self.actors[actor]

    def save_artifact(self, name: str, value):
        return self.record.artifact(name, value)

    def track_repository(self, actor: str, name: str, repository_id: int) -> None:
        """Register a repository immediately after creating it through the raw API."""
        self.github(actor)
        if not name or type(repository_id) is not int or repository_id <= 0:
            raise ValueError("Repository ownership requires a name and immutable ID")
        identity = (actor, name, repository_id)
        if identity not in self._repositories:
            self._repositories.append(identity)
            self.record.event("resource", actor=actor, name=name, id=repository_id, state="created")

    def cleanup_repositories(self) -> list[str]:
        errors = []
        for actor, name, repository_id in self._repositories[:]:
            try:
                try:
                    repo = self.github(actor).gh.get_repo(name)
                    if repo.id != repository_id:
                        raise RuntimeError(f"Refusing cleanup: repository ID changed for {name}")
                    repo.delete()
                except GithubException as exc:
                    if exc.status != 404:
                        raise
                self.record.event("resource", actor=actor, name=name, id=repository_id, state="deleted")
                self._repositories.remove((actor, name, repository_id))
            except Exception as exc:
                errors.append(str(exc))
        return errors
