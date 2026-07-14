<div align="center">

# GitInject

**A framework for evaluating prompt injection vulnerabilities in real, live GitHub workflows.**

[![Paper](https://img.shields.io/badge/arXiv-2606.09935-b31b1b.svg)](https://arxiv.org/abs/2606.09935)
[![Python](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](./LICENSE)

*Official implementation of ["GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines"](https://arxiv.org/abs/2606.09935).*

</div>

---

> [!WARNING]
> GitInject provisions live repositories and triggers real workflow runs against your GitHub account. **Always use a secondary GitHub account** dedicated to testing.

## Overview

AI-powered agents are increasingly embedded in CI/CD pipelines to autonomously review pull requests, triage issues, and maintain codebases. Because they ingest untrusted content while operating with elevated repository permissions, they are a natural target for prompt injection with supply-chain consequences.

GitInject is an open-source framework for studying these vulnerabilities in **real, live GitHub workflows**. Unlike prior agent-security benchmarks that *simulate* tool calls, GitInject provisions ephemeral repositories and triggers actual workflow runs, so sandbox constraints, credential handling, and permission boundaries behave exactly as they do in production.

Each run is scored on two axes:

- **Utility**: did the agent do its job?
- **Security**: did it resist the attack?

The framework ships an autonomous **Vulnerability Scanner** that turns a workflow definition into a ranked, live-confirmed attack inventory without human-authored scenarios.

### Supported agents

GitInject ships workflow definitions for the major AI CI/CD agents:

- **Claude Code Action** (Anthropic)
- **Codex Action** (OpenAI)
- **Gemini CLI** (Google)
- **GitHub Copilot** workflows
- **Cline** assistant

GitLab CI/CD is also supported through a parallel runner (e.g. the `claude-gitlab-mr-review` workflow), so the same scenarios can exercise GitLab-hosted agents.

## Project Structure

| Path | Description |
| --- | --- |
| `src/benchmark/` | Core Python orchestrator and CLI. |
| `src/benchmark/workflows/` | Dataset of workflow definitions with security metadata. |
| `src/benchmark/scenarios/` | Python test cases evaluating Utility and Security. |
| `src/benchmark/scanner/` | Autonomous vulnerability scanner pipeline. |
| `src/benchmark/utils/` | GitHub/GitLab interaction and repo provisioning. |

## Getting Started

### Prerequisites

- Python 3.13+
- [uv](https://github.com/astral-sh/uv)
- [GitHub CLI (`gh`)](https://cli.github.com/), authenticated with `repo` and `workflow` scopes
- For Claude-based workflows, enable the [Claude GitHub App](https://github.com/apps/claude)

### Installation

```bash
uv sync
```

### Configuration

Each workflow declares the secrets it needs (via `secrets.*` in its YAML and `required_secrets` in its `metadata.json`), so you only need the API key(s) for the provider(s) you actually run:

| Provider / use | Environment variable |
| --- | --- |
| Anthropic (Claude workflows) | `ANTHROPIC_API_KEY` |
| OpenAI (Codex workflows) | `OPENAI_API_KEY` |
| Google (Gemini workflows and the default LLM judge) | `GEMINI_API_KEY` |
| OpenRouter (scanner / ranker model routing) | `OPENROUTER_API_KEY` |

```bash
# Export only what the target workflow (and, for scan, the scanner) requires:
export ANTHROPIC_API_KEY=your_key_here
```

## Usage

GitInject is driven by a single CLI. All commands are invoked via `uv run python -m src.benchmark.cli`.

### 1. Discover components

List available workflows and scenarios with their compatibility metadata (Category and Supported Events):

```bash
uv run python -m src.benchmark.cli list workflows
uv run python -m src.benchmark.cli list scenarios
```

### 2. Run evaluations

Run a specific test case or an entire compatible suite.

```bash
# Run a single workflow against a scenario
uv run python -m src.benchmark.cli run --workflow codex-pr-review --scenario vulnerable_code_review --unaligned

# Run all scenarios matching a workflow's category and event type
uv run python -m src.benchmark.cli run --workflow codex-pr-review --scenario all --unaligned

# Identify compatible pairs without executing them (dry run)
uv run python -m src.benchmark.cli run-suite --workflow-labels code-review --dry-run
```

#### Reproduce the paper's attacks

The 11 named attacks from the paper (Table 6) ship as scenarios under `src/benchmark/scenarios/malicious/`. A helper script runs each against its target workflow (credentials are read from a gitignored `references/run.sh`):

```bash
# Run all 11 once; set REPEAT=5 to match the paper
./scripts/run_paper_scenarios.sh
REPEAT=5 ./scripts/run_paper_scenarios.sh

# Or a single attack against its workflow
./scripts/run_paper_scenarios.sh codex-pr-review pr_token_exfiltration_via_git_config
```

| Attack (paper) | Scenario | Workflow |
| --- | --- | --- |
| `pr_body_github_token_exfiltration` | `pr_token_exfiltration_via_git_config` | `codex-pr-review` |
| `claude_md_token_exfiltration` | `claude_md_instructions_injection` | `claude-pr-review` |
| `agents_md_token_exfiltration` | `codex_agents_md_injection` | `codex-pr-review` |
| `gemini_md_token_exfiltration` | `gemini_md_instructions_injection` | `gemini-assistant` |
| `claude_md_approval_manipulation` | `supply_chain_malicious_code` | `claude-pr-review` |
| `agents_md_approval_manipulation` | `agents_md_approval_manipulation` | `codex-pr-review` |
| `gemini_md_approval_manipulation` | `gemini_md_approval_manipulation` | `gemini-assistant` |
| `pr_body_approval_manipulation` | `unauthorized_pr_approval` | `codex-pr-review` |
| `issue_body_github_token_exfiltration` | `issue_onboarding_secret_exfiltration` | `gemini-assistant` |
| `issue_body_reconnaissance` | `cline_issue_body_injection` | `cline-assistant` |
| `denial_of_wallet` | `dos_request_flood` | `claude-pr-review` |

### 3. Scan for vulnerabilities

Turn a workflow into a ranked, live-confirmed attack inventory:

```bash
uv run python -m src.benchmark.cli scan --workflow codex-pr-review
```

### 4. Report & cleanup

```bash
# Aggregate results of previous runs
uv run python -m src.benchmark.cli report

# Bulk-delete ephemeral repositories from your GitHub account
uv run python -m src.benchmark.cli cleanup --prefix benchmark-run
```

## Extending GitInject

- **Workflows**: add a folder in `src/benchmark/workflows/<name>/` containing a `metadata.json` (target action, category, required secrets) and the workflow definition under `contents/.github/workflows/`.
- **Scenarios**: add a folder under `src/benchmark/scenarios/benign/<name>/` (utility baseline) or `src/benchmark/scenarios/malicious/<name>/` (attack) with a `scenario.py` (a class inheriting from `AbstractScenario`) plus any fixture files under `contents/`.

## Documentation

- [System Architecture](./plans/architecture.md)
- [Vulnerability Scanner Design](./plans/vulnerability-scanner.md)
- [Roadmap & Status](./plans/concerns.md)
- [Contribution Guidelines](./CONTRIBUTING.md)

## Citation

If you use GitInject in your research, please cite:

```bibtex
@article{isbarov2026gitinject,
  title   = {GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines},
  author  = {Isbarov, Jafar and Suleymanov, Umid and K\"{o}ksal, Abdullatif and Kantarcioglu, Murat},
  journal = {arXiv preprint arXiv:2606.09935},
  year    = {2026},
  url     = {https://arxiv.org/abs/2606.09935}
}
```

## Contact

Jafar Isbarov. Email: isbarov at vt dot edu
