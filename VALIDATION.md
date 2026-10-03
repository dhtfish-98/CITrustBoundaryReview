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
