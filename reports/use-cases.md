# AI-Powered GitHub Workflows: Purpose Taxonomy & Use Cases

This report classifies AI-powered GitHub workflows based on their intended purpose, analyzing examples from both the `src/benchmark/workflows` and the [GitHub Next Agentics](https://github.com/githubnext/agentics) datasets.

## 1. Code Maintenance & Quality
These workflows focus on improving the codebase's long-term health through automated investigation, refactoring, and verification.

| Use Case | Description | Examples |
| :--- | :--- | :--- |
| **CI Investigation** | Analyzes failed GitHub Actions runs to identify root causes and suggest fixes. | [ci-doctor.md](https://github.com/githubnext/agentics/blob/main/workflows/ci-doctor.md), [copilot-ci-doctor](../src/benchmark/workflows/copilot-ci-doctor) |
| **Test Improvement** | Identifies gaps in test coverage and generates new test cases. | [daily-test-improver.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-test-improver.md), [claude-test-analysis](../src/benchmark/workflows/claude-test-analysis) |
| **Code Simplification** | Refactors complex functions or modules to improve readability and reduce technical debt. | [code-simplifier.md](https://github.com/githubnext/agentics/blob/main/workflows/code-simplifier.md) |
| **Performance Optimization** | Analyzes code for bottlenecks and suggests performance enhancements. | [daily-perf-improver.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-perf-improver.md) |
| **Formal Verification** | Progressively applies formal verification (e.g., Lean 4) to ensure mathematical correctness. | [lean-squad.md](https://github.com/githubnext/agentics/blob/main/workflows/lean-squad.md), [copilot-lean-squad](../src/benchmark/workflows/copilot-lean-squad) |
| **Dead Code Detection** | Identifies and removes unused files or functions. | [daily-file-diet.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-file-diet.md) |

## 2. Security & Compliance
Workflows that proactively scan for vulnerabilities, malicious activity, or adherence to organizational policies.

| Use Case | Description | Examples |
| :--- | :--- | :--- |
| **Malicious Code Scanning** | Scans recent commits for suspicious patterns (e.g., exfiltration, backdoors). | [daily-malicious-code-scan.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-malicious-code-scan.md), [copilot-malicious-scan](../src/benchmark/workflows/copilot-malicious-scan) |
| **Guideline Enforcement** | Verifies that new PRs or issues follow specific contribution or security guidelines. | [contribution-guidelines-checker.md](https://github.com/githubnext/agentics/blob/main/workflows/contribution-guidelines-checker.md), [contribution-check.md](https://github.com/githubnext/agentics/blob/main/workflows/contribution-check.md) |
| **Vulnerability Analysis** | Generates VEX (Vulnerability Exploitability eXchange) reports or analyzes dependencies. | [vex-generator.md](https://github.com/githubnext/agentics/blob/main/workflows/vex-generator.md) |
| **Accessibility Review** | Automatically reviews UI changes for accessibility violations. | [daily-accessibility-review.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-accessibility-review.md) |

## 3. Triage & Management
Automated handling of the "inbox" (Issues and Discussions) to reduce maintainer burden.

| Use Case | Description | Examples |
| :--- | :--- | :--- |
| **Issue Triage** | Analyzes new issues, applies labels, and provides initial debugging notes. | [issue-triage.md](https://github.com/githubnext/agentics/blob/main/workflows/issue-triage.md), [claude-issue-triage](../src/benchmark/workflows/claude-issue-triage) |
| **Deduplication** | Identifies and labels duplicate issues to consolidate discussions. | [duplicate-code-detector.md](https://github.com/githubnext/agentics/blob/main/workflows/duplicate-code-detector.md), [claude-issue-deduplication](../src/benchmark/workflows/claude-issue-deduplication) |
| **Task Mining** | Extracts actionable tasks from high-volume GitHub Discussions. | [discussion-task-miner.md](https://github.com/githubnext/agentics/blob/main/workflows/discussion-task-miner.md) |
| **Dependabot Bundling** | Aggregates multiple Dependabot PRs/Issues into single manageable units. | [dependabot-pr-bundler.md](https://github.com/githubnext/agentics/blob/main/workflows/dependabot-pr-bundler.md), [dependabot-issue-bundler.md](https://github.com/githubnext/agentics/blob/main/workflows/dependabot-issue-bundler.md) |
| **Issue Summarization** | Provides weekly or daily summaries of active issues and progress. | [weekly-issue-summary.md](https://github.com/githubnext/agentics/blob/main/workflows/weekly-issue-summary.md) |

## 4. Content & Documentation
Workflows that treat documentation as a living entity, ensuring it stays in sync with the code.

| Use Case | Description | Examples |
| :--- | :--- | :--- |
| **Wiki Maintenance** | Automatically writes, updates, and structures GitHub Wiki pages. | [agentic-wiki-writer.md](https://github.com/githubnext/agentics/blob/main/workflows/agentic-wiki-writer.md), [copilot-wiki-writer](../src/benchmark/workflows/copilot-wiki-writer) |
| **Doc-to-Code Sync** | Updates documentation based on code changes or vice versa. | [daily-doc-updater.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-doc-updater.md), [unbloat-docs.md](https://github.com/githubnext/agentics/blob/main/workflows/unbloat-docs.md) |
| **Glossary Management** | Maintains a project-wide glossary of technical terms and concepts. | [glossary-maintainer.md](https://github.com/githubnext/agentics/blob/main/workflows/glossary-maintainer.md) |
| **Editorial Board** | Reviews technical content for style, tone, and clarity. | [tech-content-editorial-board.md](https://github.com/githubnext/agentics/blob/main/workflows/tech-content-editorial-board.md) |

## 5. Code Review & PR Automation
AI-driven feedback on Pull Requests to catch bugs, nits, and architectural issues early.

| Use Case | Description | Examples |
| :--- | :--- | :--- |
| **Semantic Code Review** | Provides deep analysis of PR changes beyond simple linting. | [claude-pr-review](../src/benchmark/workflows/claude-pr-review), [opencode-pr-review](../src/benchmark/workflows/opencode-pr-review), [codex-pr-review](../src/benchmark/workflows/codex-pr-review) |
| **Nitpicking/Style** | Focuses on smaller stylistic issues and best practices. | [pr-nitpick-reviewer.md](https://github.com/githubnext/agentics/blob/main/workflows/pr-nitpick-reviewer.md), [grumpy-reviewer.md](https://github.com/githubnext/agentics/blob/main/workflows/grumpy-reviewer.md) |
| **PR Self-Healing** | Automatically applies fixes to common PR issues (e.g., linting, small bugs). | [pr-fix.md](https://github.com/githubnext/agentics/blob/main/workflows/pr-fix.md), [claude-ci-auto-fix](../src/benchmark/workflows/claude-ci-auto-fix) |
| **Multi-Device Testing** | Coordinates and analyzes results from complex multi-device CI runs. | [daily-multi-device-docs-tester.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-multi-device-docs-tester.md) |

## 6. Support & Intelligence
General-purpose assistants that can answer questions and provide context about the repository.

| Use Case | Description | Examples |
| :--- | :--- | :--- |
| **Repo-Specific Q&A** | Answers questions about how the project works or how to contribute. | [repo-ask.md](https://github.com/githubnext/agentics/blob/main/workflows/repo-ask.md), [q.md](https://github.com/githubnext/agentics/blob/main/workflows/q.md) |
| **General Assistance** | A "Co-pilot" for the repository that can help with various tasks. | [gemini-assistant](../src/benchmark/workflows/gemini-assistant), [cline-assistant](../src/benchmark/workflows/cline-assistant), [repo-assist.md](https://github.com/githubnext/agentics/blob/main/workflows/repo-assist.md) |
| **Research & Planning** | Performs background research on issues or helps plan upcoming features. | [weekly-research.md](https://github.com/githubnext/agentics/blob/main/workflows/weekly-research.md), [daily-plan.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-plan.md) |

## 7. Reporting & Analytics
Generating human-readable insights into the state of the repository and the team.

| Use Case | Description | Examples |
| :--- | :--- | :--- |
| **Repo Chronicle** | Maintains a historical log of all significant changes and decisions. | [daily-repo-chronicle.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-repo-chronicle.md) |
| **Team Status** | Summarizes what team members have been working on across the repo. | [daily-team-status.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-team-status.md), [daily-repo-status.md](https://github.com/githubnext/agentics/blob/main/workflows/daily-repo-status.md) |
| **Repository Mapping** | Generates high-level maps of the codebase architecture and dependencies. | [weekly-repo-map.md](https://github.com/githubnext/agentics/blob/main/workflows/weekly-repo-map.md) |
