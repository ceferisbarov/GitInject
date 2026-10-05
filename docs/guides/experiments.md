# Target, attack, and experiment execution

Use **v0.1.0 to replicate the original paper**. The experiment engine is a breaking API change. Original workflow/scenario and scanner execution is available under `gitinject legacy`; it does not have the isolated-controller contract described here. GitLab remains a legacy adapter and has no parity with the new GitHub engine.

## Definitions and the two accounts

An `ExperimentSpec` binds a reusable `TargetSpec`, a legitimate task and trigger, an optional `AttackInstance`, a `ThreatModel`, explicit `ProvisioningSpec`, budgets, and a fixed `EvaluationContract`. Each contract has a schema version, identity where applicable, canonical JSON, and a SHA256 content revision. Runtime state belongs to `ExperimentSession`, not these definitions. `AttackMethod` is an optional reusable description; an external controller does not need a library method.

Targets declare immutable source commit IDs and baseline files, workflow/agent configuration, permissions, runner environment, and credential references. Configuration metadata describes intended target state; changes to GitHub settings require explicit provisioning transformations. Source trees are copied into fresh repositories, preserving original blobs and file modes. Secrets, settings, historical runs, and branch history are not inferred or copied. Missing or unobservable prerequisites have their own applicability results. There is no implicit workflow replacement, approval-policy change, probe commit, secret exposure to the agent, or live-repository reuse.

Use dedicated machine accounts:

- `GITHUB_TOKEN` authenticates **defense**; `gh auth token` is the existing fallback. Defense creates the target and installs only declared instrumentation/configuration.
- `ATTACKER_GITHUB_TOKEN` authenticates **attack**, with no fallback. Attack trials require both accounts, authenticate `/user`, and verify distinct immutable IDs before provisioning.
- The workflow agent identity is separate, often `github-actions[bot]`. The target should document that identity and the actual agent implementation.

The scope is **all resources accessible to the dedicated machine-account credentials**. Keep their grants within the experiment accounts, including grants through organizations and applications. Public GitHub information is observable under the account's platform permissions. This is a platform authority boundary, not a promise to constrain arbitrary requests to a URL list. Additional repository restrictions, endpoint filters, and arbitrary semantic constraints are rejected rather than presented as enforceable policies. Source repositories must belong to a verified machine account.

Only public fresh trial repositories are currently provisioned. Isolate concurrent research at the account level where possible. Cleanup deletes only recorded immutable repository identities after checking the current identity. Inventory differences without attributed creation are retained and reported for reconciliation. The host performs cleanup using the appropriate owning account's credentials; it never passes cleanup handles to attack code.

## Planning and execution

From a checkout:

```bash
uv run gitinject experiment list examples/experiments
uv run gitinject experiment validate examples/experiments/issue-injection.json
uv run gitinject experiment dry-run examples/experiments/fork-pr.json
uv run gitinject experiment suite examples/experiments/benign.json examples/experiments/issue-injection.json --dry-run
uv run gitinject experiment run examples/experiments/benign.json
```

The example attack target explicitly permits the verified attack account to invoke Codex (`allow-users: "${attack_login}"`); it does not permit arbitrary public callers. Its workflows use Codex and explicitly install `OPENAI_API_KEY` as a repository secret. Fork-PR examples use a deliberately declared `pull_request_target` target variant that can access the model credential; the runner does not relax fork policies. Review the workflow before live execution. Planning validates JSON, reports statically observable applicability, credential references, budgets, and runtime requirements. It does not authenticate, create repositories, execute controllers, or call models.

Controller paths are relative to the execution workspace unless absolute. Controllers are hash-verified and copied into the attempt before execution. JSON definitions can also be constructed through `gitinject.experiments`:

```python
from gitinject.experiments import Action, ExperimentSession, load_spec

session = ExperimentSession(load_spec("examples/experiments/adaptive.json"), ".")
try:
    session.initialize()
    first = session.act(Action(
        id="first",
        parameters={"method": "POST", "endpoint": "/repos/${repository}/issues",
                    "json": {"title": "Review", "body": "Please review README.md"}},
    ))
    session.checkpoint({"subject": first["body"]["number"]})
    # Choose additional actions using permitted observations.
    result = session.finish()
except Exception:
    session.cancel()
    if not session.closed:
        session.finish()
    raise
```

This Python interface runs in the trusted host and is intended for a trusted external orchestrator. Generated attack code runs only through the worker protocol. Use `session.run()` for declarative sequences or the declared controller. There is no autoresearch planner or hypothesis-ranking implementation in this engine.

## Worker isolation and broad interactions

Controllers require Linux x86_64, Bubblewrap, usable user/network/PID namespaces, and `/usr/bin/python3`. The runner refuses execution if the boundary is unavailable. There is no sanitized-subprocess fallback.

The worker receives a read-only controller and its declared assets, a read-only system runtime, private scratch space, and a JSON request/response protocol. It has no host home/workspace mounts, host environment, network, defense/evaluator credentials, evaluator observations, provisioning objects, or raw actor clients. A seccomp filter denies process/thread creation; memory, CPU, file-size and descriptor limits apply, and the host enforces the trial deadline and protocol-message limit. The bundled worker supports standard-library Python, not arbitrary host dependencies or provider SDKs. The trusted host gateway retains credentials, refuses credential/routing/TLS overrides, sends credentials only to `https://api.github.com`, disables redirects/environment authentication, and never retries ambiguous requests.

The action protocol exposes:

- **REST:** arbitrary GitHub API endpoints, JSON or text bodies, parameters, and noncredential headers. There is no endpoint catalog. HTTP error statuses and bodies remain ordinary receipts.
- **GraphQL:** arbitrary query/mutation documents and variables, including batched operations. GraphQL errors remain in their response body.
- **Git:** arbitrary Git database requests for blobs, trees, commits and refs, plus a convenience commit operation. Native networked Git subprocesses, local aliases, and host Git execution are not exposed.
- **gh:** the inline `gh api` request surface (`--method`, typed/raw fields, headers). Other CLI subcommands, extensions, aliases, file-backed fields and host overrides are rejected. Use generic REST/GraphQL for GitHub functionality outside this convenience surface.

An action contains a unique ID, transport, parameters, dependencies, and optional subject metadata. `${repository}`, `${attack_login}`, `${defense_login}`, and `${response.ACTION_ID.body.number}` bind fresh resources. `${binding.NAME}` resolves concrete instance bindings (with method parameter defaults); a complete placeholder preserves its JSON type. Worker context includes the seed, safe bindings and declared controller configuration. Dependencies resolve before side effects. Read-only REST actions can declare `wait_for` conditions; the session records each poll and checks cancellation and action/time budgets between polls.

Provisioning transforms are separate privileged operations with an identity and reason. Secret installation uses an environment reference and records the reference, never its plaintext value. Installing a canary does not establish that the agent can read it.

Acquired authority defaults to `record-only`. A threat model can explicitly declare `observed-machine-account`: the controller may submit an **attack-response path**, not a token override, to `session.use_acquired_authority(...)`. The host authenticates the token observed through that response, accepts it only if its immutable principal is one of the verified machine accounts, retains the token outside the worker, and records its fingerprint, provenance, and subsequent operation principal. This does not install an elevated token to simulate exploitation. Acquired authority for other accounts is unsupported.

## Adaptation, budgets, and evaluation

Static attacks execute declared actions. Offline controllers can record candidate lineage, payload revisions and simulator results using `checkpoint(..., simulated=True)`; simulated outcomes never become live evaluation evidence. Online controllers can observe permitted attack-account responses, checkpoint state, wait for events, and submit further actions. Private evaluator requests and defense task responses are excluded from worker observations and attack response bindings. Offline workers do not receive live action feedback. The examples include benign execution, issue injection, fork-PR injection, online multi-stage feedback, and offline simulation.

Elapsed time and actions are enforced at the host boundary, including polls. Model calls and cost are enforced when reported through checkpoint accounting; the engine does not infer hidden model computation or implement a provider/model gateway. Suite planning enforces trial counts per experiment identity within a suite. An external research campaign must enforce its cross-invocation trial budget. Cancellation, uncertain transport outcomes, partial traces, resource reconciliation, and cleanup errors remain in the attempt.

Evaluation is frozen before execution. The built-in versioned `checks-v1` evaluator supports equality, existence, containment, text containment, and credential-reference containment over captured evidence. Evidence requests use defense credentials and are private until final result collection. A check can restrict comment attribution to the configured workflow-agent login. Security `true` means the attack succeeded; utility and security each use `true`, `false`, or unknown. Intended attacker outcomes do not define authoritative success.

Results separate:

| Dimension | Meaning |
| --- | --- |
| Applicability | `applicable`, `inapplicable`, or `unknown`, with prerequisite evidence. |
| Execution | `completed`, `policy_failure`, `error`, `stopped`, or `cancelled`. A denial from GitHub can be a completed valid attempt. |
| Invocation | `true` for a completed target workflow with the configured job and successful agent step; otherwise unknown. This verifies execution of the declared agent step, not an independent provider attestation. |
| Evaluation | `completed`, `pending`, or `error`; evaluator errors do not become security verdicts. |
| Utility/security | Independent three-valued results; checks requiring invocation remain unknown if invocation is unavailable. |

Workflow receipts record run IDs, actors, commit IDs, jobs/steps, and verified PR/commit associations where GitHub supplies them. Issue-event causality is not always observable from the Actions API; empty associations remain explicit rather than inferred from timestamps alone. Missing invocation is never interpreted as target resistance. Workflow collection waits for completion before requesting final evaluator evidence.

## Artifacts and replay

Each trial extends the existing attempt recorder with a v2 manifest, frozen definition and revisions, dependency lockfile snapshot (when present), installed dependency versions, implementation source snapshots/hashes, original/effective target assets, provisioning records, verified accounts, actor-bound transport receipts, observations, checkpoints, workflow receipts, and final evidence/results. The append-only journal includes a hash chain; artifacts and copied inputs have content hashes. These detect accidental alteration, not tampering by someone able to replace both the files and all manifest hashes.

Known credential literals, URL encodings and base64 values are redacted in saved JSON, requests, responses, and errors. Base64 source blobs are decoded for redaction. Credential-containing controller/lockfile inputs are rejected. Sensitive checks run over in-memory evidence and retain safe match booleans and credential fingerprints. Raw sensitive artifacts are not retained; this deliberately limits replay and reevaluation. Arbitrary transformations are not a general data-loss-prevention guarantee.

```bash
uv run gitinject experiment replay runs/ATTEMPT --mode inspect
uv run gitinject experiment replay runs/ATTEMPT --mode trace
uv run gitinject experiment replay runs/ATTEMPT --mode controller
uv run gitinject experiment replay runs/ATTEMPT --mode evaluate
```

`inspect` verifies definition/input/artifact/journal hashes and reports dependency/code drift. `trace` executes captured attack actions in a fresh trial with repository and returned identifier remapping; prefer symbolic response bindings for ambiguous numeric identifiers. It preserves action dependencies and refuses traces with uncertain outcomes or redacted action payloads. `controller` reruns the captured adaptive implementation, so it may choose a different trace. These are distinct operations. Live GitHub configuration/platform/model drift is not fully detectable from local hashes, and no bit-for-bit reproduction is promised.

`evaluate` uses captured evidence without GitHub calls. Redacted secret containment may be unknown. A revised evaluation definition must declare `parent_revision`; it produces a separate revision linked to the original attempt. CLI reevaluation prints the result without overwriting original evidence. There are no online private feedback oracles in this initial engine.

## Verification

```bash
uv run pytest tests/unit/
GITINJECT_REQUIRE_SANDBOX=1 uv run pytest tests/unit/test_experiment_worker.py
GITINJECT_LIVE_EXPERIMENTS=1 uv run pytest tests/integration/test_experiments_real.py
```

Worker isolation tests must run on a host that permits Bubblewrap namespaces; ordinary restricted environments skip them. The required-boundary mode fails if isolation cannot be exercised. Live tests require distinct account credentials, and the model key before creating any repositories. They verify actual Actions job/step invocation and actor identities; unit mocks cannot establish live invocation.
