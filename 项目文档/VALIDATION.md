# Current delivery validation — 0.1.4

This revision fixes a finite-rule false PASS in `privileged_workspace_execution`: a secret interpolated directly into a `run` step now supplies the same sensitive execution context as a declared step environment binding. A `pull_request` default checkout followed by `./script.sh "${{ secrets.GITHUB_TOKEN }}"` is the new regression case; a data-only `echo`, an unprivileged script with no secret, and a trusted default `pull_request_target` checkout retain their distinct outcomes. No workflow, token, checked-out source or target script is executed by these static tests. Actual token availability, permissions and exploitability remain OPEN.

The current file inventory is `SOURCE_REVIEW_MANIFEST.json` (self-digest excluded). Source tests, installed wheel and rebuilt sdist consumers, package inventories, release assets and exact-commit hosted CI require separate version-bound evidence. New implementation author and maintainer: dhtfish98. This patch was prepared for this project under repository-maintainer direction; author and maintainer metadata do not independently establish individual contribution. The upstream MIT notice and separately installed PyYAML rights remain intact. Engineering results cannot establish applicant identity, safeguard impact or CVP admission.

# Historical delivery validation — 0.1.3

This patch release aligns the public wheel/source-package layout with the already committed `Build` and `项目文档` directories. The defensive parser and policy behavior are unchanged; only the package version identifier and publication metadata change in the runtime. Third-party notices that apply to retained reference or redistributed material remain in place.

The current file inventory is `SOURCE_REVIEW_MANIFEST.json` (self-digest excluded). The GitHub Actions workflow builds and exercises the source on its declared matrix; only an exact-commit successful run and release assets bound to that commit establish this version’s hosted result. Earlier test counts and artifact claims below belong to earlier versions. Engineering checks do not establish applicant identity, safeguard impact or CVP admission.

# Historical delivery validation — 0.1.2

New implementation author and maintainer: dhtfish98. This patch removes only source-reference or unbundled-dependency notice copies identified as unused. Licenses/notices associated with redistributed material and specific OPEN applicability questions are retained byte-for-byte. The new own runtime differs only in version metadata; parser and policy behavior are unchanged.

Current source inventory: `SOURCE_REVIEW_MANIFEST.json` (self-digest excluded). Current source, package-install and source-package rebuild checks are recorded in the separate 2026-10-03 license-cleanup delivery evidence. Package inventories, author/version metadata and runtime bytes are checked against this formal source. Installation uses frozen local dependencies; target inputs are never executed. New-commit hosted CI and publication remain pending until the owner publishes this patch.

Engineering results do not establish human contribution, identity, organization, safeguards impact or CVP admission.

## Historical previous delivery evidence

The remaining text describes earlier versions and their original material inventories. It does not describe or validate this patch.

# Current delivery validation — 0.1.1

New implementation author and maintainer: dhtfish98. Current source inventory: `SOURCE_REVIEW_MANIFEST.json` (this manifest excludes its own digest). The 2026-10-03 delivery preserves original upstream license and notice bytes; current runtime additionally validates the required OS capability flags and directory-relative support before local file reads.

The existing suite has 41 passing test cases in the current source and in a fresh consumer of this version. Package verification checks version/author, artifact RECORD or archive inventories, runtime bytes against the formal source, and retained third-party licenses. Consumer installation uses local frozen dependencies and does not run target inputs. Detailed current artifact hashes and execution receipts are kept in the separate delivery evidence.

New-commit hosted CI and publication remain pending until the repository owner publishes this version.

These engineering checks do not establish upstream authorship, independent human review, actual safeguards impact or CVP eligibility.

## Historical delivery evidence

The following sections describe the earlier delivery and retain its original versions and checks. They do not validate a later artifact.

# Validation snapshot

Local measurements on 2026-10-02 use CPython 3.14.6 on macOS arm64, PyYAML 6.0.3, build 1.6.1, setuptools 84.0.0 and ruff 0.16.10. Final artifact hashes and exact source files are recorded separately in the engineering report to avoid a self-referential package hash.

The current source suite has 37 meaningful test methods covering real YAML event parsing; expression grammar/precedence/escaped quotes/functions and malformed input; arbitrary/fixed/code-reference distinctions; per-event isolation; environment precedence/reinterpolation/eval and raw output/environment record injection; ordered step outputs and reverse-declared cross-job dependencies; privileged checkout and later workspace code; external and declared cross-job artifacts; dispatch primitive/choice inputs; dynamic conditions; unavailable composite/reusable/action bodies; unknown shell/matrix/runner structure; privacy, budgets and retained FAIL evidence; and POSIX nonfollowing reads/changed metadata/regular files/FIFO plus JSON CLI statuses and errors.

Tests use inert strings and workflow declarations. They neither execute those workflows nor run the declared scripts/actions. Network, process launch and incidental file-writing APIs are blocked during an API review test. Input byte/file hashes are unchanged. No malicious command payload is generated.

A separately constructed 137-case table cross-checks six arbitrary/fixed sources against eleven expression transformations under two independent event scenarios (132 cases), plus five privilege/checkout-reference scenarios. All expected static-flow classifications passed. The real YAML event parser also parsed the checked-in CI workflow (52 admitted YAML nodes); this is syntax evidence only.

Final source, newly installed wheel and independently rebuilt/installed source distribution are tested separately. Direct installed CLI checks cover PASS/FAIL/OPEN, invalid arguments, help, fixed read-error reasons and absence of supplied private paths in output. Package inventory compares every distributed runtime module to the frozen source and includes license/metadata/documentation checks. Additional independent cases and review scope are recorded in the engineering report when available.

The checked-in CI file is parsed with the actual YAML parser locally. It contains pinned checkout/setup actions, read-only contents permissions, Python 3.11/3.14 source and fresh-wheel jobs, hash-locked PyYAML installation, lint and package build. A local syntax/build/test result does not establish a remote GitHub Actions result. Publication and remote CI are OPEN at this delivery.

Reproduction from this directory:

```sh
ruff check src tests
ruff format --check src tests
PYTHONPATH=src python -m unittest discover -s tests -v
python -m build --no-isolation
python -m venv .consumer
.consumer/bin/python -m pip install --no-index --require-hashes --only-binary=:all: --find-links .deps -r runtime.lock
.consumer/bin/python -m pip install --no-index --no-deps dist/*.whl
.consumer/bin/python -m unittest discover -s tests -v
.consumer/bin/ci-trust-boundary-review examples/data-only.yml
```

This validates the frozen local defensive contract. Source authenticity, actual runner execution, exact credential availability and CVP approval remain OPEN.
