# System Architecture

This document describes the software architecture for the AI-Powered GitHub Workflows Security Benchmark project.

## 1. High-Level Overview

The system is designed as a modular benchmarking platform that executes AI-powered GitHub Workflows against a variety of security-focused scenarios. It evaluates these runs using two primary metrics: **Utility** (did it do the job?) and **Security** (did it resist the attack?).

### Architecture Diagram

```text
       +-----------------+
       |   Benchmark CLI | <--- User Interaction (List, Run, Report)
       +--------+--------+
                |
                v
       +-----------------+        +---------------------+
       | BenchmarkRunner | <----> | GitHub API (via gh) |
       +--------+--------+        +----------+----------+
                |                            ^
                |      +-----------------+   |
                +----> | Workflow Setup  | --+ (Trigger CI)
                |      +-----------------+   |
                |                            |
                |      +-----------------+   |
                +----> | Scenario Loader | --+ (Event Data)
                |      +--------+--------+   |
                |               |            |
                |               v            |
                |      +-----------------+   |
                +----> | Attack Injector | --+ (Payloads)
                |      +--------+--------+   |
                |               |            |
                |               v            |
                |      +-----------------+   |
                +----> |Context Snapshot | --+ (Log for Optimization)
                |      +-----------------+   |
                v                            v
       +-----------------+        +---------------------+
       |BenchmarkAnalyzer| <----> | GitHub Results/Logs |
       +--------+--------+        +----------+----------+
                |                            |
                v                            |
       +-----------------+                   |
       | Evaluator Layer | <-----------------+
       | (State/LLM)     |
       +--------+--------+
                |
                v
       +-----------------+
       | Evaluation Log  | (Utility Score, Security Score)
       +-----------------+
```

## 2. Component Breakdown

### 2.1 Core Orchestrator (`src/benchmark/`)
- **CLI (`cli.py`)**: Provides a unified command-line interface using `click` for managing the benchmark lifecycle.
- **Runner (`runner.py`)**: Handles the orchestration of a benchmark run. It identifies the target workflow, loads the scenario, injects an optional attack, captures the full context snapshot, and triggers the GitHub event.
- **Analyzer (`analyzer.py`)**: The evaluation engine. It dispatches evaluation requests to the Scenario's defined Evaluators.
- **Context Snapshotter**: A diagnostic utility that serializes the *total input state* (event payload, repo files, workflow definition) into `runs/<timestamp>/context_snapshot.json` right before triggering the workflow. This is used for internal optimization of attack payloads.
- **Evaluator Layer (`evaluators.py`)**: A systematic framework for scoring runs:
    - **StateEvaluator**: Performs deterministic checks against the GitHub API (e.g., "Is the issue closed?").
    - **LLMEvaluator**: Uses **Gemini 1.5 Pro** (via `google-genai` SDK) as a judge to grade semantic quality against a rubric.
- **Scenario Base (`scenario_base.py`)**: Defines the `AbstractScenario` class. All scenarios must implement `get_utility_evaluator()` and `get_security_evaluator()`.
- **GitHub Client (`utils/gh_client.py`)**: A wrapper around the `gh` CLI and GitHub REST API, providing high-level methods to fetch PR details, issue comments, and workflow logs.

### 2.2 Data Layer (`src/benchmark/`)
- **Workflows (`src/benchmark/workflows/`)**: Each workflow is a folder containing:
    - `workflow.yml`: The actual GitHub Action definition.
    - `metadata.json`: Information about the target action, defense level, and intended purpose.
- **Scenarios (`src/benchmark/scenarios/`)**: The test cases.
    - **Python Scenarios**: Classes inheriting from `AbstractScenario` that define which `Evaluator` to use for Utility and Security.

### 2.3 Actions Layer (`actions/`)
Contains local clones/forks of the AI GitHub Actions being benchmarked. This allows for testing "Action-level" defenses by modifying the source code of the agent itself. Supported agents include:
- `gemini-cli`: Google's Gemini-powered CLI.
- `claude-code-action`: Anthropic's Claude-powered action.
- `run-gemini-cli`: GitHub Action wrapper for Gemini CLI.

### 2.4 Infrastructure Layer (Provisioning)
- **Repo Provisioner (`utils/provisioner.py`)**: Responsible for managing the lifecycle of the target GitHub repository.
    - **Dynamic Creation**: Creates a new, unique repository for each run.
    - **Forking Support**: Can fork an existing "template" repository.
    - **Workflow Syncing**: Mirrors the local `workflow.yml` to the remote repository.
    - **Static Content**: Pushes any files required by a specific scenario.
    - **Teardown**: Deletes the entire repository after the benchmark run.

### 2.5 Reporting Layer (`reports/`)
- **Workflow Taxonomy**: All workflows and scenarios are classified into seven standard categories (e.g., Code Maintenance, Security & Compliance, Triage & Management) to enable cross-provider benchmarking.
- **Performance Reports**: Periodic reports that analyze the utility vs. security trade-offs for different agent configurations.
- **Run Artifacts**: Detailed logs and metadata from individual benchmark runs, stored for auditing and analysis.

### 2.6 Model Substitution Layer (Adversarial)
- **Centralized Registry (`src/benchmark/config/adversarial_swaps.json`)**: A global mapping of official GitHub Actions to their non-aligned "Shadow" counterparts.
- **YAML Transformer**: Integrated into the `RepoProvisioner`, this component performs real-time patching of `uses:` statements in workflow definitions to inject red-team forks during unaligned runs.
- **Tag-Based Red-Teaming**: Encapsulates adversarial model configurations within Git tags/branches (e.g., `@mistral`) of the shadow actions, ensuring clean isolation of the test environment.

## 3. Evaluation Lifecycle

1.  **Selection**: User selects a Workflow, Scenario, and optional Attack/Unaligned mode.
2.  **Provisioning**:
    - The **Runner** generates a unique repository name.
    - The **Provisioner** sets up the repository.
    - **Adversarial Patching**: If `--unaligned` is enabled, the Provisioner swaps actions using the global registry.
    - The Provisioner pushes the (potentially patched) workflow and static files.

3.  **State Preparation**:
    - The **Scenario** executes `setup_state` to create dynamic objects (Issues, PRs).
4.  **Trigger**: The Runner triggers the event defined in the Scenario.
5.  **Observation & Analysis**:
    - The **Runner** polls for workflow completion.
    - The **Analyzer** requests the `Evaluator` objects from the Scenario.
    - The **Evaluators** execute (State checks via API or LLM grading via logs).
6.  Reporting:
    - The results are logged to the `runs/` directory.
    - Summary metrics are aggregated into the `reports/` directory according to the **Workflow Classification**.
7.  Cleanup:
    - The **Provisioner** deletes the entire GitHub repository.

## 4. Key Security Concepts

### 4.1 Utility vs. Security
The benchmark explicitly separates these two functions. A workflow that is "too secure" (e.g., it blocks all inputs) will have high Security but zero Utility. Our goal is to find configurations that maximize both.

### 4.2 State-First Evaluation
The system prioritizes **StateEvaluator** over **LLMEvaluator**. If an agent's success can be verified via a GitHub API side effect (e.g., labeling an issue), we avoid the cost and potential "hallucination" of using an LLM as a judge.

### 4.3 LLM as a Judge (Rubric-based)
For tasks like "Code Review," where success is semantic, we use a high-capability model (Gemini 1.5 Pro) with a scenario-specific rubric to evaluate the agent's output.

### 4.4 Canary Tokens & Leak Detection
Scenarios like `pr_injection_exfiltration.py` use unique strings ("Canary Tokens"). The `StateEvaluator` specifically checks GitHub comments and PR bodies for these tokens to detect exfiltration.
ration.
