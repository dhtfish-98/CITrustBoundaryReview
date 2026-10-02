import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import textwrap
import unittest
from dataclasses import replace
from unittest.mock import patch

from ci_trust_boundary_review import Limits, RULES, review
from ci_trust_boundary_review.cli import main
from ci_trust_boundary_review.contracts import Flow, OpenInput
from ci_trust_boundary_review.expressions import evaluate, fences, parse
from ci_trust_boundary_review.input import parse_yaml, read_local


def workflow(steps, event="pull_request_target", job_extra="", top_extra=""):
    return (
        f"on: {event}\n"
        + top_extra
        + "jobs:\n  review:\n    runs-on: ubuntu-latest\n"
        + job_extra
        + "    steps:\n"
        + textwrap.indent(textwrap.dedent(steps).strip() + "\n", "      ")
    ).encode()


class Expressions(unittest.TestCase):
    def value(self, text):
        return evaluate(
            parse(text, Limits()),
            lambda p: Flow(arbitrary=p[-1] == "title", unknown=p[-1] == "unknown"),
        )

    def test_literals_precedence_escaping_and_fences(self):
        for text, value in [
            ("true", True),
            ("null", None),
            ("-2.5e2", -250.0),
            ("0xFF", 255),
            ("'it''s }} fixed'", "it's }} fixed"),
            ("true || false && false", True),
            ("false && 'unused' || 'selected'", "selected"),
        ]:
            with self.subTest(text=text):
                actual = self.value(text)
                self.assertTrue(actual.known)
                self.assertEqual(actual.literal, value)
        spans = list(fences("a ${{ 'it''s }}' }} b ${{ github.title }}"))
        self.assertEqual(len(spans), 2)
        self.assertEqual(spans[0][2].strip(), "'it''s }}'")

    def test_boolean_functions_do_not_return_their_input(self):
        for expression in [
            "github.title == 'literal'",
            "!github.title",
            "contains(github.title, 'a')",
            "startsWith(github.title, 'a')",
            "endsWith(github.title, 'a')",
            "hashFiles(github.title)",
        ]:
            with self.subTest(expression=expression):
                self.assertFalse(self.value(expression).flow.arbitrary)
        for expression in [
            "github.title || 'safe'",
            "'nonempty' && github.title",
            "format('{0}', github.title)",
            "toJSON(github.title)",
            "join(github.title, ',')",
            "case(true, github.title, 'safe')",
        ]:
            self.assertTrue(self.value(expression).flow.arbitrary)
        self.assertFalse(self.value("false && github.title").flow.arbitrary)

    def test_context_indices_case_and_complex_access(self):
        self.assertTrue(self.value("GITHUB['TITLE']").flow.arbitrary)
        self.assertTrue(self.value("github[github.title]").flow.unknown)
        self.assertFalse(self.value("github[github.title]").flow.arbitrary)
        self.assertTrue(self.value("fromJSON(github.title).value").flow.unknown)
        self.assertTrue(self.value("fromJSON(github.title).value").flow.arbitrary)
        self.assertTrue(self.value("github.*.title").flow.unknown)

    def test_invalid_syntax_and_function_arities(self):
        for expression in [
            "",
            "github.",
            "github.title + 1",
            '"value"',
            "github['x'",
            "foo()",
            "contains('a')",
            "format('a')",
            "case(true, 'a')",
            "1e999",
            "fromJSON()",
            "true false",
        ]:
            with self.subTest(expression=expression), self.assertRaises(OpenInput):
                parse(expression, Limits())
        with self.assertRaises(OpenInput):
            list(fences("${{ 'incomplete }}"))

    def test_non_ascii_numbers_and_syntax_are_open_without_crashing(self):
        for expression in [".²", ".١", "1١ == 11", "1\u00a0&& false", "true\u2028||false"]:
            with self.subTest(expression=expression), self.assertRaises(OpenInput):
                parse(expression, Limits())
            report = review(workflow("- run: echo '${{ " + expression + " }}'", "push"))
            self.assertEqual(report["status"], "OPEN")
            self.assertFalse(report["complete"])
        self.assertEqual(self.value("'café'").literal, "café")

    def test_expression_depth_token_and_char_budgets(self):
        for value, limits in [
            ("(" * 40 + "true" + ")" * 40, Limits()),
            ("true || false", replace(Limits(), expression_tokens=2)),
            ("github.title", replace(Limits(), expression_chars=3)),
        ]:
            with self.assertRaises(OpenInput):
                parse(value, limits)


class Workflows(unittest.TestCase):
    def rules(self, report):
        return {finding["rule"] for finding in report["findings"]}

    def test_real_yaml_on_key_and_event_only_labeler_exception(self):
        for event in ["push", "pull_request_target", "workflow_run"]:
            r = review(workflow("- run: echo hello", event))
            self.assertEqual(r["status"], "PASS")
            self.assertEqual(r["events"], [event])
        r = review(workflow("- uses: actions/labeler@v5"))
        self.assertEqual(r["status"], "PASS")
        self.assertFalse(r["permission_policy_checked"])
        self.assertFalse(r["action_pin_policy_checked"])

    def test_direct_event_text_to_run_quoted_or_not(self):
        for path in [
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.head_ref",
            "GITHUB.EVENT.PULL_REQUEST.TITLE",
            "github['event']['pull_request']['title']",
        ]:
            r = review(workflow("- run: echo '${{ " + path + " }}'"))
            self.assertIn("expression_to_run", self.rules(r))
            self.assertEqual(r["status"], "FAIL")

    def test_fixed_values_and_boolean_results(self):
        for expression in [
            "github.run_id",
            "github.event.pull_request.number",
            "github.event.pull_request.head.sha",
            "steps.first.outcome",
            "github.event.pull_request.title == 'a'",
            "contains(github.event.pull_request.title, 'a')",
            "false && github.event.pull_request.title",
        ]:
            r = review(
                workflow("- id: first\n  run: echo hello\n- run: echo '${{ " + expression + " }}'")
            )
            self.assertEqual(r["status"], "PASS", expression)

    def test_unknown_or_malformed_expression_is_open(self):
        for expression in [
            "github.event.nonexistent",
            "vars.TEXT",
            "matrix.name",
            "fromJSON(github.event.pull_request.title).title",
            "github.event[inputs.name].title",
            "unknown()",
            "github..title",
        ]:
            r = review(workflow("- run: echo '${{ " + expression + " }}'"))
            self.assertFalse(r["complete"])
            self.assertTrue(r["open_reasons"])
        r = review(workflow("- run: echo '${{ github.event.pull_request.title'"))
        self.assertEqual(r["status"], "OPEN")

    def test_environment_isolation_and_reinterpolation(self):
        data = workflow("""
            - env:
                TITLE: ${{ github.event.pull_request.title }}
              run: printf '%s\\n' "$TITLE"
        """)
        r = review(data)
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(
            r["observations"][0]["kind"], "environment_used_as_data_in_literal_command"
        )
        r = review(data.replace(b"printf '%s\\n' \"$TITLE\"", b"echo '${{ env.TITLE }}'"))
        self.assertIn("environment_to_code", self.rules(r))

    def test_environment_eval_and_interpreter_code(self):
        for command in [
            'eval "$TITLE"',
            'bash -c "$TITLE"',
            'sh -c "$TITLE"',
            'python3 -c "$TITLE"',
            'node -e "$TITLE"',
            "$TITLE",
        ]:
            r = review(
                workflow(
                    "- env:\n    TITLE: ${{ github.event.pull_request.title }}\n  run: " + command
                )
            )
            self.assertIn("environment_to_eval", self.rules(r), command)

    def test_environment_scope_override_and_case_collision(self):
        global_env = "env:\n  TITLE: ${{ github.event.pull_request.title }}\n"
        safe = review(
            workflow(
                "- env:\n    TITLE: fixed\n  run: echo '${{ env.TITLE }}'", top_extra=global_env
            )
        )
        self.assertEqual(safe["status"], "PASS")
        collision = review(
            workflow(
                '- env:\n    TITLE: ${{ github.event.pull_request.title }}\n    title: fixed\n  run: eval "$TITLE"'
            )
        )
        self.assertEqual(collision["status"], "FAIL")
        self.assertIn("ambiguous_environment_case", collision["open_reasons"])
        wrong_case = review(
            workflow(
                '- env:\n    TITLE: ${{ github.event.pull_request.title }}\n  run: eval "$title"'
            )
        )
        self.assertEqual(wrong_case["status"], "OPEN")
        self.assertFalse(wrong_case["findings"])

    def test_step_output_chain_and_safe_output_counterexample(self):
        for source, status in [
            ("${{ github.event.pull_request.title }}", "FAIL"),
            ("fixed", "PASS"),
        ]:
            r = review(
                workflow(
                    """
                - id: emit
                  env:
                    TITLE: SOURCE
                  run: echo "result=$TITLE" >> "$GITHUB_OUTPUT"
                - run: echo '${{ steps.emit.outputs.result }}'
            """.replace("SOURCE", source)
                )
            )
            self.assertEqual(r["status"], status)
            if status == "FAIL":
                self.assertIn("step_output_to_code", self.rules(r))

    def test_environment_file_chain(self):
        r = review(
            workflow("""
            - env:
                TITLE: ${{ github.event.pull_request.title }}
              run: echo "LATER=$TITLE" >> "$GITHUB_ENV"
            - run: echo '${{ env.LATER }}'
        """)
        )
        self.assertIn("environment_to_code", self.rules(r))

    def test_unknown_writer_and_future_outputs_open(self):
        for producer in [
            '- id: emit\n  run: cat ./inert >> "$GITHUB_OUTPUT"',
            "- id: emit\n  uses: local/unknown@v1",
            '- id: emit\n  run: echo "$UNKNOWN=value" >> "$GITHUB_OUTPUT"',
        ]:
            r = review(workflow(producer + "\n- run: echo '${{ steps.emit.outputs.result }}'"))
            self.assertEqual(r["status"], "OPEN")
        self.assertEqual(
            review(workflow("- run: echo '${{ steps.future.outputs.result }}'"))["status"], "OPEN"
        )

    def test_cross_job_needs_output_chain(self):
        text = """
            on: pull_request_target
            jobs:
              later:
                runs-on: ubuntu-latest
                needs: producer
                steps:
                  - run: echo '${{ needs.producer.outputs.title }}'
              producer:
                runs-on: ubuntu-latest
                outputs:
                  title: ${{ steps.emit.outputs.value }}
                steps:
                  - id: emit
                    env:
                      TITLE: ${{ github.event.pull_request.title }}
                    run: printf '%s\\n' "value=$TITLE" >> "$GITHUB_OUTPUT"
        """
        r = review(textwrap.dedent(text).encode())
        self.assertIn("needs_output_to_code", self.rules(r))
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual(
            review(textwrap.dedent(text).replace("needs: producer", "needs: missing").encode())[
                "status"
            ],
            "OPEN",
        )

    def test_privileged_checkout_and_workspace_consumption(self):
        text = """
            - uses: actions/checkout@v4
              with:
                ref: ${{ github.event.pull_request.head.sha }}
            - run: bash ./inert.sh
        """
        r = review(workflow(text))
        self.assertTrue(
            {"privileged_untrusted_checkout", "privileged_workspace_execution"} <= self.rules(r)
        )
        r = review(workflow(text, "pull_request"))
        self.assertNotIn("privileged_untrusted_checkout", self.rules(r))
        self.assertNotIn("privileged_workspace_execution", self.rules(r))
        r = review(workflow(text.replace("bash ./inert.sh", "echo hello")))
        self.assertNotIn("privileged_workspace_execution", self.rules(r))

    def test_default_checkout_event_scenarios_do_not_cross_contaminate(self):
        r = review(
            workflow(
                "- uses: actions/checkout@v4\n- run: bash ./inert.sh",
                "[pull_request, pull_request_target]",
            )
        )
        self.assertEqual(r["status"], "OPEN")
        self.assertFalse(r["findings"])
        r = review(
            workflow(
                "- uses: actions/checkout@v4\n  with:\n    ref: ${{ github.sha }}\n- run: bash ./inert.sh",
                "pull_request",
            )
        )
        self.assertEqual(r["status"], "PASS")

    def test_privilege_context_is_not_a_separate_permission_rule(self):
        r = review(workflow("- run: echo hello", "push", top_extra="permissions: write-all\n"))
        self.assertEqual(r["status"], "PASS")
        r = review(
            workflow(
                "- uses: actions/checkout@v4\n- run: ./inert.sh",
                "pull_request",
                top_extra="permissions: write-all\n",
            )
        )
        self.assertIn("privileged_workspace_execution", self.rules(r))

    def test_unknown_checkout_reference_and_literal_base(self):
        for reference in ["main", "${{ vars.REF }}"]:
            r = review(
                workflow(
                    "- uses: actions/checkout@v4\n  with:\n    ref: "
                    + reference
                    + "\n- run: bash ./inert.sh"
                )
            )
            self.assertEqual(r["status"], "OPEN")
        r = review(
            workflow(
                "- uses: actions/checkout@v4\n  with:\n    ref: ${{ github.ref }}\n- run: echo hello"
            )
        )
        self.assertEqual(r["status"], "PASS")
        self.assertNotIn("privileged_untrusted_checkout", self.rules(r))

    def test_raw_record_writers_poison_other_names(self):
        for target, reference in [
            ("GITHUB_ENV", "env.SAFE"),
            ("GITHUB_OUTPUT", "steps.emit.outputs.other"),
        ]:
            steps = (
                '- id: emit\n  env:\n    TITLE: ${{ github.event.pull_request.title }}\n  run: echo "value=$TITLE" >> "$'
                + target
                + "\"\n- run: echo '${{ "
                + reference
                + " }}'"
            )
            r = review(workflow(steps, top_extra="env:\n  SAFE: fixed\n"))
            self.assertEqual(r["status"], "FAIL")
            self.assertFalse(r["complete"])
        r = review(
            workflow("""
            - id: emit
              env:
                TITLE: ${{ github.event.pull_request.title }}
              run: |
                echo "other=fixed" >> "$GITHUB_OUTPUT"
                echo "value=$TITLE" >> "$GITHUB_OUTPUT"
            - run: echo '${{ steps.emit.outputs.other }}'
        """)
        )
        self.assertIn("step_output_to_code", self.rules(r))

    def test_action_script_and_uninspected_body(self):
        r = review(
            workflow(
                "- uses: actions/github-script@v7\n  with:\n    script: console.log('${{ github.event.pull_request.title }}')"
            )
        )
        self.assertIn("expression_to_action_script", self.rules(r))
        self.assertFalse(r["complete"])
        self.assertIn("action_script_body_effects_unknown", r["open_reasons"])

    def test_workflow_run_artifact_to_execution_and_data_only(self):
        producer = """
            - uses: actions/download-artifact@v5
              with:
                name: inert-data
                run-id: ${{ github.event.workflow_run.id }}
        """
        producer = textwrap.dedent(producer).strip()
        execute = review(workflow(producer + "\n- run: bash ./inert.sh", "workflow_run"))
        self.assertIn("artifact_to_execution", self.rules(execute))
        self.assertEqual(execute["status"], "FAIL")
        self.assertFalse(execute["complete"])
        read = review(workflow(producer + "\n- run: cat ./inert.txt", "workflow_run"))
        self.assertEqual(read["status"], "OPEN")
        self.assertNotIn("artifact_to_execution", self.rules(read))

    def test_cross_job_artifact_producer_chain(self):
        text = """
            on: pull_request_target
            jobs:
              producer:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
                  - uses: actions/upload-artifact@v4
                    with:
                      name: inert-bundle
                      path: ./inert
              consumer:
                runs-on: ubuntu-latest
                needs: producer
                steps:
                  - uses: actions/download-artifact@v5
                    with:
                      name: inert-bundle
                  - run: python3 ./inert.py
        """
        r = review(textwrap.dedent(text).encode())
        self.assertIn("artifact_to_execution", self.rules(r))
        self.assertFalse(r["complete"])

    def test_dispatch_number_boolean_choice_and_string(self):
        for kind, options, status in [
            ("number", "", "PASS"),
            ("boolean", "", "PASS"),
            ("choice", "        options: [info, warning]\n", "PASS"),
            ("choice", "        options: ['unsafe space']\n", "OPEN"),
            ("string", "", "FAIL"),
        ]:
            text = (
                "on:\n  workflow_dispatch:\n    inputs:\n      value:\n        type: "
                + kind
                + "\n"
                + options
                + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo '${{ inputs.value }}'\n"
            )
            self.assertEqual(review(text.encode())["status"], status)

    def test_literal_false_skips_but_dynamic_conditions_remain_open(self):
        r = review(workflow("- if: false\n  run: echo '${{ github.event.pull_request.title }}'"))
        self.assertEqual(r["status"], "PASS")
        r = review(
            workflow(
                "- if: github.event.pull_request.head.repo.fork == false\n  run: echo '${{ github.event.pull_request.title }}'"
            )
        )
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("dynamic_condition_not_proven", r["open_reasons"])

    def test_composite_reusable_matrix_unknown_shell_and_structure_open(self):
        examples = [
            workflow("- uses: ./.github/actions/inert"),
            workflow("- uses: owner/unknown@v1"),
            b"on: push\njobs:\n  a:\n    uses: owner/repo/.github/workflows/inert.yml@main\n",
            workflow(
                "- run: echo hello",
                job_extra="    strategy:\n      matrix:\n        name: [a, b]\n",
            ),
            workflow("- run: echo hello\n  shell: pwsh"),
            workflow("- parallel:\n    - run: echo hello"),
            workflow("- run: if true; then echo hello; fi"),
            workflow("- run: unknown-command --inert"),
        ]
        for data in examples:
            self.assertEqual(review(data)["status"], "OPEN")

    def test_unknown_execution_poison_cannot_hide_later_flow(self):
        r = review(
            workflow("""
            - run: unknown-command
            - env:
                TITLE: ${{ github.event.pull_request.title }}
              run: eval "$TITLE"
        """)
        )
        self.assertEqual(r["status"], "FAIL")
        self.assertFalse(r["complete"])

    def test_unknown_yaml_features_and_duplicates(self):
        data = workflow("- run: echo hello", "push")
        cases = [
            data + b"---\non: push\n",
            data.replace(b"on: push", b"on: !!str push"),
            data.replace(b"echo hello", b"&inert echo hello"),
            b"on: push\non: pull_request\njobs: {}\n",
            b"on: push\njobs: {a: {steps: [], steps: []}}\n",
            b"[one, two]",
            b"on: [\xff]",
            b"on: push\nx: &a {k: v}\ny: *a\njobs: {}\n",
            b"on: push\njobs: {<<: {}}\n",
            b"%YAML 1.2\n---\non: push\njobs: {}\n",
        ]
        for value in cases:
            self.assertEqual(review(value)["status"], "OPEN")

    def test_budgets_and_known_finding_survives_partial_analysis(self):
        data = workflow("- run: echo '${{ github.event.pull_request.title }}'\n- run: echo hello")
        r = review(data, replace(Limits(), steps=1))
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("step_budget", r["open_reasons"])
        for key, cap in [
            ("input_bytes", 10),
            ("yaml_nodes", 3),
            ("yaml_depth", 1),
            ("scalar_chars", 3),
            ("expression_chars", 3),
            ("expressions", 1),
            ("report_bytes", 2048),
        ]:
            source = (
                data
                if key != "expressions"
                else data.replace(b"echo hello", b"echo '${{ github.run_id }}'")
            )
            if key == "report_bytes":
                source = workflow("\n".join(["- run: echo '${{ github.head_ref }}'"] * 30))
            r = review(source, replace(Limits(), **{key: cap}))
            self.assertFalse(r["complete"], key)
            self.assertTrue(r["open_reasons"], key)
            if key == "input_bytes":
                self.assertIsNone(r["input_sha256"])
                self.assertEqual(r["input_digest_status"], "OPEN")
                with patch(
                    "ci_trust_boundary_review.review.hashlib.sha256",
                    side_effect=AssertionError("oversized_hash"),
                ):
                    self.assertEqual(
                        review(source, replace(Limits(), input_bytes=cap))["status"], "OPEN"
                    )
            if key == "report_bytes":
                self.assertLessEqual(len(json.dumps(r, sort_keys=True).encode()), cap)
        r = review(
            workflow(
                "- run: echo '${{ github.event.pull_request.title }}'\n- run: echo '${{ github.head_ref }}'"
            ),
            replace(Limits(), findings=1),
        )
        self.assertEqual(r["status"], "FAIL")
        self.assertGreater(r["finding_count"], len(r["findings"]))

    def test_rule_set_and_permanent_open_boundaries(self):
        self.assertEqual(len(RULES), 9)
        r = review(workflow("- run: echo hello"))
        for field in (
            "actual_execution",
            "source_authenticity",
            "credential_availability",
            "cvp_eligibility",
        ):
            self.assertEqual(r[field], "OPEN")
        for invalid in [0, False, {}, "limits"]:
            with self.assertRaises(TypeError):
                review(b"on: push", invalid)
        for key, value in [
            ("steps", False),
            ("steps", 0),
            ("expression_depth", 1000),
            ("input_bytes", 999999999),
        ]:
            with self.assertRaises(ValueError):
                replace(Limits(), **{key: value})

    def test_no_network_process_writes_and_private_values_not_reported(self):
        marker = "INERT_PRIVATE_834120"
        data = workflow(
            "- env:\n    SECRET_NAME: "
            + marker
            + "\n  run: echo '${{ github.event.pull_request.title }}' # "
            + marker,
            top_extra="name: " + marker + "\n",
        )
        before = hashlib.sha256(data).hexdigest()
        with (
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
            patch.object(Path, "write_text", side_effect=AssertionError("write")),
        ):
            r = review(data)
        self.assertEqual(hashlib.sha256(data).hexdigest(), before)
        self.assertNotIn(marker, json.dumps(r))
        self.assertNotIn("SECRET_NAME", json.dumps(r))
        self.assertNotIn("pull_request.title", json.dumps(r))

    def test_source_positions_are_scalar_starts(self):
        data = b"on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo '${{ github.event.pull_request.title }}'\n"
        r = review(data)
        self.assertEqual(r["findings"][0]["sink"], {"line": 6, "column": 14})
        root, _ = parse_yaml(data, Limits())
        self.assertEqual(root.get("on").value, "pull_request_target")


class LocalReaderAndCLI(unittest.TestCase):
    def test_regular_input_unchanged_and_nonfollowing_paths(self):
        with tempfile.TemporaryDirectory(dir=".") as temporary:
            directory = Path(temporary).absolute()
            path = directory / "inert.yaml"
            data = workflow("- run: echo hello", "push")
            path.write_bytes(data)
            self.assertEqual(read_local(str(path), Limits()), data)
            (directory / "alias").symlink_to(path)
            (directory / "linkdir").symlink_to(directory, target_is_directory=True)
            os.mkfifo(directory / "fifo")
            for target in [
                directory / "alias",
                directory / "linkdir" / "inert.yaml",
                directory / "fifo",
                directory,
                directory / ".." / directory.name / "inert.yaml",
            ]:
                with self.assertRaises(OpenInput):
                    read_local(str(target), Limits())
            self.assertEqual(path.read_bytes(), data)

    def test_metadata_change_and_read_budget(self):
        with tempfile.TemporaryDirectory(dir=".") as temporary:
            path = str(Path(temporary).absolute() / "inert.yaml")
            Path(path).write_bytes(b"abc")
            with self.assertRaises(OpenInput):
                read_local(path, replace(Limits(), input_bytes=2))
            original = os.fstat
            calls = []

            def changed(fd):
                value = original(fd)
                calls.append(value)
                if len(calls) == 2:
                    from types import SimpleNamespace

                    return SimpleNamespace(
                        st_dev=value.st_dev,
                        st_ino=value.st_ino,
                        st_size=value.st_size,
                        st_mtime_ns=value.st_mtime_ns + 1,
                        st_ctime_ns=value.st_ctime_ns,
                    )
                return value

            with patch.object(os, "fstat", side_effect=changed), self.assertRaises(OpenInput):
                read_local(path, Limits())

    def test_cli_statuses_and_fixed_errors_without_path_echo(self):
        with tempfile.TemporaryDirectory(dir=".") as temporary:
            path = Path(temporary).absolute() / "INERT_PRIVATE_PATH.yaml"
            for data, exit_code in [
                (workflow("- run: echo hello"), 0),
                (workflow("- run: echo '${{ github.head_ref }}'"), 1),
                (workflow("- uses: owner/unknown@v1"), 2),
            ]:
                path.write_bytes(data)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main([str(path)]), exit_code)
                r = json.loads(output.getvalue())
                self.assertNotIn("INERT_PRIVATE_PATH", output.getvalue())
                self.assertEqual(r["cvp_eligibility"], "OPEN")
        for args in [
            [],
            ["PRIVATE", "--unknown"],
            ["PRIVATE", "--max-input-bytes", "PRIVATE"],
            ["PRIVATE", "--max-input-bytes", "-1"],
        ]:
            output, error = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                try:
                    code = main(args)
                except SystemExit as exited:
                    code = exited.code
            self.assertEqual(code, 2)
            self.assertNotIn("PRIVATE", output.getvalue() + error.getvalue())
            self.assertEqual(json.loads(output.getvalue())["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()
