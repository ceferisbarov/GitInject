# Contributing to AI-Powered GitHub Workflows Security Benchmark

Thank you for your interest in contributing to this project! We welcome contributions in the form of new benchmark workflows, security scenarios, bug fixes, or documentation improvements.

## How to Contribute

### 1. Adding a New Workflow
Workflows are located in `src/benchmark/workflows/`. To add a new one:
1. Create a new directory named after your workflow (e.g., `gemini-pr-reviewer`).
2. Add a `workflow.yml` which is the actual GitHub Action definition.
3. Add a `metadata.json` with the following structure:
   ```json
   {
     "name": "Friendly Name",
     "description": "What this workflow does",
     "category": "code-review | triage-management | security-compliance | ...",
     "provider": "google-gemini | anthropic-claude | ...",
     "defense_level": "baseline | hardened | sandboxed",
     "labels": ["label1", "label2"],
     "supported_events": ["pull_request", "issues"]
   }
   ```
   *Note: Refer to `src/benchmark/utils/types.py` for the full list of allowed categories and providers.*

### 2. Adding a New Scenario
Scenarios are located in `src/benchmark/scenarios/`. To add a new one:
1. Create a new `.py` file.
2. Inherit from `AbstractScenario` (from `src.benchmark.scenario_base`).
3. Implement the required methods: `setup_state`, `teardown_state`, `get_event`, **`get_utility_evaluator`**, and **`get_security_evaluator`**.

#### Choosing an Evaluator
We use a systematic evaluation framework. Choose the one that best fits your scenario:
- **`StateEvaluator` (Preferred)**: For deterministic checks against the GitHub API (e.g., verifying an issue was closed, a label was added, or a branch exists).
- **`LLMEvaluator`**: For semantic quality checks (e.g., grading a code review). Requires a clear rubric.
- **`AlwaysPassEvaluator` / `AlwaysFailEvaluator`**: For benign scenarios or where a specific metric isn't applicable.

### 3. Development & Testing
We use `uv` for dependency management and `pytest` for testing.

#### Setup
```bash
uv sync
```

#### Running Tests
Always ensure your changes pass the existing unit tests. If you add a new scenario or evaluator, you **must** add corresponding unit tests in `tests/unit/`.
```bash
# Run all unit tests
PYTHONPATH=. uv run pytest tests/unit/
```

*Note: Tests involving `LLMEvaluator` require a valid `GEMINI_API_KEY` environment variable, though most are mocked in unit tests.*

### 4. Code Style
We use `ruff` for linting and formatting. Please run it before submitting a PR:
```bash
uv run ruff check .
uv run ruff format .
```

## Security Disclosure
If you find a security vulnerability in the benchmark suite itself, please report it via the contact information in the main README.

## License
By contributing, you agree that your contributions will be licensed under the project's existing license.
