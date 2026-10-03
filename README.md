# CITrustBoundaryReview


New implementation author: **dhtfish98**. Current project version: **0.1.2**.

A new bounded offline static analyzer for the `ctbr-1` workflow trust-boundary contract. It reads one explicitly supplied local GitHub Actions workflow. It parses YAML events and GitHub expression syntax, then follows declared values through ordered steps, job dependencies, environment bindings, output files and artifact declarations. It does not run the workflow.

Install the wheel with the separately supplied trusted `PyYAML==6.0.3` dependency. The dependency is an actual YAML parser; no upstream zizmor library or executable is installed or called. The hash-locked dependency file is included; PyYAML retains its MIT notices in its separately installed distribution. The retained zizmor MIT notice applies to the explicitly unresolved capability-selection provenance, not to vendored Rust runtime.

```sh
python -m pip install --require-hashes --only-binary=:all: -r runtime.lock
python -m pip install --no-deps .
ci-trust-boundary-review examples/data-only.yml
```

The command emits one JSON report and exits `0` for PASS, `1` for FAIL, or `2` for OPEN. Invalid arguments and local-read failures produce fixed JSON reasons without echoing supplied paths or values. `--help` prints ordinary help. `--max-input-bytes` can lower the default input budget. The Python API is `review(workflow_bytes, Limits())`; it accepts bytes and never reads additional workflow inputs implicitly.

PASS means the frozen rules found no modeled boundary crossing and no unresolved selected mechanism. FAIL means at least one potential static flow was identified. It does not prove exploitability or actual execution. OPEN marks unsupported syntax, unavailable bodies, uncertain flow, or exhausted budgets. FAIL and OPEN can coexist: the status stays FAIL, `complete` becomes false and `open_reasons` remains visible. A budget can truncate displayed evidence while `finding_count` preserves already identified alerts.

`actual_execution`, `source_authenticity`, `credential_availability`, and `cvp_eligibility` are always OPEN, including a parsing PASS. Project relevance is separate from application approval. Human authorship, identity, organization eligibility and approval are not established by this repository or a passing test.

The nine frozen rules are:

| Rule | Declared boundary examined |
| --- | --- |
| `expression_to_run` | Arbitrary event/input text interpolated into a `run` script |
| `expression_to_action_script` | Arbitrary text interpolated into `actions/github-script`'s script |
| `privileged_untrusted_checkout` | An untrusted code reference or repository declared in checkout under a potentially privileged context |
| `privileged_workspace_execution` | Selected literal workspace execution after an untrusted checkout, including local action execution |
| `step_output_to_code` | A tracked step output later interpolated into code |
| `environment_to_code` | A tracked environment value later reinterpolated into code |
| `needs_output_to_code` | A tracked exported job output later interpolated into code |
| `environment_to_eval` | Arbitrary tracked data passed to a selected shell/interpreter code argument |
| `artifact_to_execution` | A tracked artifact code origin later consumed by selected workspace execution |

One sink chooses its most specific output/environment channel rule rather than counting the same interpolation under every rule. Different event scenarios are analyzed separately. `pull_request_target` and `workflow_run` provide potentially privileged context; their presence alone creates no finding. Declared write permissions, a job environment and a modeled secret binding can also provide context. Permission strength, least privilege, action pin quality and secret contents are expressly not checked. A simple modeled labeler workflow can PASS this finite contract without establishing the labeler's provenance or complete safety.

Expressions are parsed by a new bounded lexer and precedence parser: literals, single-quote escaping, dotted or literal-string indexed contexts, parentheses, `!`, comparisons, `&&`, `||`, and the explicitly enumerated built-in functions. Comparisons and boolean-returning functions produce fixed booleans; `&&` and `||` preserve operand-returning flow. `format`, `join` and `toJSON` preserve arbitrary content. `fromJSON`, wildcard/computed access and unresolved contexts remain OPEN. No arbitrary expression is evaluated as Python, JavaScript or shell code. Constant booleans can suppress a statically disabled step; dynamic conditions are retained as possible execution and OPEN rather than accepted as proven security guards.

The source table is deliberately finite and embedded in `review.py`. It distinguishes arbitrary title/body/comment/head-ref strings, fixed numeric/SHA/status values, and untrusted code references. A SHA can be safe for string interpolation while still selecting untrusted code. PR and workflow-run payload fields outside their relevant event scenario remain OPEN. Dispatch number/boolean declarations and a finite choice list with `[A-Za-z_0-9.-]` options are fixed; string/environment inputs are arbitrary. Unmodeled contexts are OPEN. No API payload is fetched to establish a value's actual type or authenticity.

Environment precedence is workflow, job, then step. Earlier modeled `GITHUB_ENV` writes persist. POSIX shell variables use their exact case; case collisions in expression environment bindings remain OPEN. The shell subset uses `shlex` and recognizes literal `echo`/`printf` single-record writes to `GITHUB_OUTPUT` or `GITHUB_ENV`. Arbitrary raw values can introduce new records, so they also poison other output/environment names and keep uncertainty visible. Unknown commands or workspace program bodies can produce unknown outputs and environment changes. Job outputs propagate through a statically ordered `needs` graph; unresolved dependencies, cycles, forward step outputs and ambiguous case collisions remain OPEN.

Literal command models cover `eval`, `bash/sh -c`, `python/python3 -c`, `node -e`, Ruby/Perl code arguments, relative scripts, `source`, and common package/build command names. A tracked environment value used by a literal `echo` or `printf` data command produces a narrowly scoped observation. This observation is not a general escaping or sanitization proof. Compound shell control flow, substitutions, pipelines, command prefixes, custom shells, working directories, omitted executable bodies and unknown effects remain OPEN. Static literal program contents are not audited for independently dangerous operations.

Recognized action models are exactly `actions/checkout`, `actions/github-script`, `actions/labeler`, `actions/upload-artifact`, and `actions/download-artifact`. Their implementation and authenticity are not fetched. Unknown remote actions, local composite bodies and reusable workflows are OPEN. GitHub-script body effects are OPEN even when its interpolation is understood. Artifact names are linked conservatively between declared producer and consumer jobs; payloads and layouts are not inspected. An external artifact declaration on `workflow_run` is a potentially untrusted code origin. Merely reading an artifact as data produces no execution finding. Unresolved names, producers, external identities and all missing artifact payloads remain OPEN. Workspace origins are conservatively combined; this is not a proof that a downloaded path is the exact later executed file.

YAML parsing is constructor-free. `on` is preserved as a string key. Duplicate or complex mapping keys, merge keys, anchors, aliases, explicit tags, directives, multiple documents, malformed UTF-8, and unsupported structures are OPEN. Default shell inference supports literal Ubuntu hosted-runner labels; other runner/default-shell situations, matrix strategies, job/workflow defaults, containers and services are OPEN. Jobs and steps use a conservative ASCII identifier subset. This is a workflow review contract, not a complete GitHub schema validator or a full shell/JavaScript interpreter.

Evidence contains fixed reason/rule identifiers, event classes, source/sink positions, channel classes, counts, budgets and a SHA-256 for admitted input bytes. An input exceeding the byte budget is not hashed: its digest is null and its digest status is OPEN. Failed local reads do not report an unobserved complete-file hash. It contains no scripts, workflow/job/step names, environment names or values, output names, artifact names, URLs, tokens or input paths. Positions are the actual YAML scalar start in one-based Unicode line/column units; they are not claimed as an exact physical expression-character location inside folded or quoted scalars.

Default limits are 1 MiB input, depth 32, 20,000 YAML nodes, 65,536 scalar characters, 128 jobs, 2,048 total admitted scenario-steps, 8,192 expressions, 8,192 characters/512 tokens/depth 32 per expression, 1,024 findings/observations and 1 MiB JSON. API limits can only be lowered; JSON budgets have a 2,048-byte minimum for fixed metadata. Displayed evidence is reduced in batches when necessary rather than repeatedly serializing one item less at a time. POSIX CLI reading rejects raw `..` components, follows no symbolic links at any component, refuses nonregular files, uses nonblocking/close-on-exec descriptors and checks metadata before and after bounded reads. Unsupported platforms stay OPEN.

See [ORIGIN.md](ORIGIN.md), [DEFENSIVE_SCOPE.md](DEFENSIVE_SCOPE.md), [SOURCE_REVIEW.json](SOURCE_REVIEW.json) and [VALIDATION.md](VALIDATION.md) for fixed source evidence and measured checks.

GitHub's current primary documentation describes text interpolation into temporary scripts, privileged-event risk, and operand-returning expression syntax: [script injections](https://docs.github.com/en/actions/concepts/security/script-injections), [event contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), and [expressions](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions). The finite model above is an explicit conservative implementation contract, not a claim of complete GitHub execution equivalence.

Local-file capability boundary: required OS flags must be exact positive integers. Descriptor walking also requires declared `os.open` directory-relative support. Missing, null, zero, boolean or otherwise invalid required capabilities return a controlled OPEN result before file access. Native Windows local-file reading is outside this POSIX profile.
