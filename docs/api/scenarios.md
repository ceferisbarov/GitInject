# Scenarios and discovery

The scenario loader expects one concrete `AbstractScenario` subclass per Python definition. The runtime state is a mutable dictionary shared with `RunContext.state`. Fixture paths are discovered relative to the loaded scenario directory, including when loaded from an attempt snapshot.

For authoring, start with [Python scenarios](../guides/scenarios.md); for arbitrary API operations, use [research experiments](../guides/research.md).

::: gitinject.scenario_base.AbstractScenario
    options:
      members: [__init__, labels, category, scenario_type, required_actors, prepare, trigger, observe, cleanup, get_preflight_evaluator, get_attack_goal, get_injection_slots, apply_attack, get_required_files, get_required_secrets, get_secrets, get_template_repo, setup_state, teardown_state, get_event, get_utility_evaluator, get_security_evaluator, to_json]

## Discovery contract

`scenario_definition` resolves a directory or definition path. Directories must contain exactly one `scenario.py` or `recipe.json`. `discover_scenario_paths` recursively discovers definitions outside fixture/cache directories and rejects duplicate directory IDs. `find_scenario` prefers an existing local path, then searches dataset IDs.

`load_scenario` executes Python module code, requires exactly one locally defined concrete subclass, constructs it with `workspace_dir`, and assigns `scenario_dir`. JSON definitions must be named `recipe.json` and are interpreted by the recipe loader. Discovery does not construct authenticated runners; loading Python is still executable code.

::: gitinject.scenario_loader
    options:
      members: [scenario_definition, discover_scenario_paths, find_scenario, load_scenario]
