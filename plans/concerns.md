# Project Concerns & Technical Debt

- [x] Suboptimal fixed-interval polling in `BenchmarkRunner` for workflow completion. (Improved with `tenacity` exponential backoff)
- [ ] Potential command injection risk in `GitHubClient.run_gh` from unsanitized scenario data.
- [x] Inconsistent mix of `gh` CLI and `gh api` calls in `GitHubClient`. (Mostly replaced with PyGitHub, `run_gh` kept for logs only)
- [ ] Non-standard error handling (returning dictionaries instead of raising exceptions).
- [ ] Sparse unit test coverage for core logic-heavy components like `Analyzer` and `Runner`.
- [ ] Sparse integration test coverage
- [x] Use `AbstractScenario` to store contents subfolder to contain the temporary repo contents.
- [x] Excessive reliance on `time.sleep()` for GitHub consistency; needs robust polling with backoff. (Using `tenacity`)
- [ ] Limited attack signatures in `BenchmarkAnalyzer` (misses data exfiltration and unauthorized API calls).
- [ ] run multiple cases at once, aggregate metrics (Bulk Execution)
- [ ] if temporary repo exists, it should throw error, not modify the repo
- [ ] simulate issues/prs/comments created by owner/member/external 
- [ ] cant use keywords on utility and security functions
- [x] need to log everything before deleting the repo (Implemented: saves metadata, logs, and context snapshots)
- [ ] multiple workflows: for now, we poll for ANY workflow. this may require a better solution 
- [x] we should comply with githubs terms: (Implemented RateLimiter in `GitHubClient`)
- [x] MUST BE model agnostic (Implemented via Adversarial Substitution Framework)
- [ ] Implement Refusal Detection in `BenchmarkAnalyzer` to identify when a model safety filter masks a vulnerability.
- [ ] Complete `mistral`/`unaligned` instrumentation for all supported actions in `actions/`.
- [x] fix metadata format & update metadata for existing workflows
- [x] create labels: coding vs. triage, pr vs. issue, analysis, create prs (Implemented via Workflow Classification)
- [ ] create docs
- [ ] human readable error message if creating a second fork of the same repo
- [ ] the following run resulted in security: true but attack was not successful: `uv run python -m src.benchmark.cli run --workflow codex-pr-review --scenario pr_injection_exfiltration --unaligned --no-cleanup`
- [ ] `CODEX_MODEL` env variable is ignored in codex action

## High Priority Roadmap
- [ ] **Refusal Detection**: Enhance `LLMEvaluator` and `Analyzer` to detect when a model refuses an instruction due to internal safety guardrails.
- [ ] **Workflow Run Trigger**: Add support for `workflow_run` events in `BenchmarkRunner` to test agentic workflows that react to CI failures.
- [x] **Bulk Execution**: Implement a mechanism to run a matrix of (Workflows x Scenarios) and generate an aggregate report.
- [ ] **Refine Evaluation**: Move from binary SUCCESS/FAILURE to a nuanced scoring system (0-10) with detailed reasoning.
