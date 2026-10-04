"""Build dataset catalogs without importing or executing scenario definitions."""

import ast
import json
from pathlib import Path

import mkdocs_gen_files

ROOT = Path(__file__).resolve().parent.parent
SOURCE_URL = "https://github.com/ceferisbarov/GitInject/blob/master/"


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def source_link(path, label):
    return f"[{label}]({SOURCE_URL}{path.relative_to(ROOT).as_posix()})"


def enum_values():
    tree = ast.parse((ROOT / "src/gitinject/utils/types.py").read_text())
    values = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, ast.Assign) and isinstance(member.value, ast.Constant):
                    for target in member.targets:
                        if isinstance(target, ast.Name):
                            values[f"{node.name}.{target.id}"] = member.value.value
    return values


ENUMS = enum_values()


def static_value(node):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return ENUMS.get(f"{node.value.id}.{node.attr}", "dynamic")
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return "dynamic"


with mkdocs_gen_files.open("reference/workflows.md", "w") as handle:
    handle.write("# Workflow catalog\n\n")
    handle.write("Generated from workflow metadata in this checkout. IDs link to their metadata definitions. ")
    handle.write("Metadata describes selection; inspect the YAML for actual triggers and permissions.\n\n")
    handle.write("| Workflow | Platform | Provider | Category | Supported events |\n")
    handle.write("| --- | --- | --- | --- | --- |\n")
    for path in sorted((ROOT / "src/gitinject/workflows").glob("*/metadata.json")):
        metadata = json.loads(path.read_text())
        row = [
            source_link(path, f"`{path.parent.name}`"),
            metadata.get("platform", "github"),
            metadata.get("provider", "—"),
            metadata.get("category", "—"),
            ", ".join(metadata.get("supported_events", [])),
        ]
        handle.write("| " + " | ".join(cell(item) for item in row) + " |\n")
    handle.write("\nSee [workflow metadata](workflow-metadata.md) and [add a workflow](../guides/workflows.md).\n")
mkdocs_gen_files.set_edit_path("reference/workflows.md", "docs/_generate.py")

with mkdocs_gen_files.open("reference/scenarios.md", "w") as handle:
    handle.write("# Scenario catalog\n\n")
    handle.write("Generated statically from Python declarations in this checkout. IDs link to their definitions. ")
    handle.write("Dynamic declarations are shown as `dynamic`; use the CLI listing to resolve trusted scenario code.\n\n")
    handle.write("| Scenario | Type | Platform | Category | Event | Required actors |\n")
    handle.write("| --- | --- | --- | --- | --- | --- |\n")
    for path in sorted((ROOT / "src/gitinject/scenarios").glob("*/*/scenario.py"), key=lambda p: p.parent.name):
        tree = ast.parse(path.read_text())
        classes = [
            node for node in tree.body
            if isinstance(node, ast.ClassDef)
            and any(isinstance(base, ast.Name) and base.id == "AbstractScenario" for base in node.bases)
        ]
        if len(classes) != 1:
            raise ValueError(f"Cannot catalog scenario class in {path}")
        scenario = classes[0]
        attributes = {}
        for node in scenario.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        attributes[target.id] = static_value(node.value)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                attributes[node.target.id] = static_value(node.value)
        events = set()
        for node in scenario.body:
            if isinstance(node, ast.FunctionDef) and node.name == "get_event":
                for descendant in ast.walk(node):
                    if isinstance(descendant, ast.Dict):
                        for key, value in zip(descendant.keys, descendant.values):
                            if isinstance(key, ast.Constant) and key.value == "event_type":
                                events.add(str(static_value(value)))
        actors = attributes.get("required_actors", ("owner",))
        row = [
            source_link(path, f"`{path.parent.name}`"),
            attributes.get("scenario_type", "benign"),
            attributes.get("platform", "github"),
            attributes.get("category", "none"),
            ", ".join(sorted(events)) or "custom",
            ", ".join(actors) if isinstance(actors, (list, tuple)) else actors,
        ]
        handle.write("| " + " | ".join(cell(item) for item in row) + " |\n")
    handle.write("\nSee [scenario authoring](../guides/scenarios.md) and [research experiments](../guides/research.md).\n")
mkdocs_gen_files.set_edit_path("reference/scenarios.md", "docs/_generate.py")
