"""Shared, credential-free scenario discovery and loading."""

import hashlib
import importlib.util
import inspect
import sys
from pathlib import Path

from .scenario_base import AbstractScenario


def scenario_definition(path: str | Path) -> Path:
    path = Path(path)
    if path.is_dir():
        definitions = [path / name for name in ("scenario.py", "recipe.json") if (path / name).is_file()]
        if len(definitions) != 1:
            raise ValueError(f"Expected exactly one scenario.py or recipe.json in {path}")
        return definitions[0]
    if not path.is_file() or path.suffix not in {".py", ".json"}:
        raise ValueError(f"Scenario definition not found: {path}")
    return path


def discover_scenario_paths(root: str | Path) -> list[Path]:
    root = Path(root)
    if not root.exists():
        return []
    paths = []
    for directory in sorted({p.parent for name in ("scenario.py", "recipe.json") for p in root.rglob(name)}):
        if not {"contents", "__pycache__"}.intersection(directory.relative_to(root).parts):
            paths.append(scenario_definition(directory))
    names = [path.parent.name for path in paths]
    if len(names) != len(set(names)):
        raise ValueError("Duplicate scenario IDs in dataset")
    return paths


def find_scenario(root: str | Path, identifier: str) -> Path | None:
    direct = Path(identifier)
    if direct.exists():
        return scenario_definition(direct)
    matches = [path for path in discover_scenario_paths(root) if path.parent.name == identifier]
    return matches[0] if matches else None


def load_scenario(path: str | Path, workspace_dir: str) -> AbstractScenario:
    definition = scenario_definition(path).resolve()
    if definition.suffix == ".json":
        from .scanner.recipe_scenario import load_recipe

        if definition.name != "recipe.json":
            raise ValueError("JSON scenarios must use recipe.json")
        scenario = load_recipe(str(definition.parent), workspace_dir)
    else:
        content = definition.read_bytes()
        name = "gitinject_scenario_" + hashlib.sha256(content).hexdigest()[:16]
        spec = importlib.util.spec_from_file_location(name, definition)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            exec(compile(content, str(definition), "exec"), module.__dict__)
        except BaseException:
            sys.modules.pop(name, None)
            raise
        classes = [
            cls
            for cls in vars(module).values()
            if inspect.isclass(cls)
            and cls.__module__ == name
            and issubclass(cls, AbstractScenario)
            and not inspect.isabstract(cls)
        ]
        if len(classes) != 1:
            raise ValueError(f"Expected exactly one concrete scenario class in {definition}")
        scenario = classes[0](workspace_dir)
    scenario.scenario_dir = str(definition.parent)
    return scenario
