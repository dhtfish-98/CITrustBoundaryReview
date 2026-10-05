"""Offline ordered flow analysis for the frozen ctbr-1 rule contract."""

import hashlib
import json
import re
from dataclasses import asdict

from . import expressions
from .contracts import SAFE, UNKNOWN, Flow, Limits, OpenInput, fallback, merge
from .input import mapping, parse_yaml, scalar, sequence
from .shell import inspect


RULES = (
    "expression_to_run",
    "expression_to_action_script",
    "privileged_untrusted_checkout",
    "privileged_workspace_execution",
    "step_output_to_code",
    "environment_to_code",
    "needs_output_to_code",
    "environment_to_eval",
    "artifact_to_execution",
)
_ID = re.compile(r"[A-Za-z_][A-Za-z_0-9-]*")
_FIXED_CHOICE = re.compile(r"[A-Za-z_0-9.-]{1,128}")
_ARBITRARY = {
    "github.head_ref",
    "github.ref",
    "github.ref_name",
    "github.base_ref",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.repo.full_name",
    "github.event.pull_request.head.label",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.display_title",
    "github.event.workflow_run.head_repository.full_name",
}
_CODE_REFS = {
    "github.head_ref",
    "github.ref",
    "github.ref_name",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.repo.full_name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_repository.full_name",
}
_FIXED = {
    "github.sha",
    "github.run_id",
    "github.run_number",
    "github.run_attempt",
    "github.actor_id",
    "github.repository_id",
    "github.repository_owner_id",
    "github.event_name",
    "github.job",
    "github.event.number",
    "github.event.issue.number",
    "github.event.pull_request.number",
    "github.event.pull_request.head.sha",
    "github.event.pull_request.base.sha",
    "github.event.workflow_run.id",
    "github.event.workflow_run.run_number",
    "github.event.workflow_run.run_attempt",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.conclusion",
    "github.event.workflow_run.status",
    "runner.os",
    "runner.arch",
    "runner.debug",
    "job.status",
}
_EVENTS = {
    "push",
    "pull_request",
    "pull_request_target",
    "workflow_run",
    "issues",
    "issue_comment",
    "discussion",
    "discussion_comment",
    "workflow_dispatch",
    "schedule",
    "release",
    "workflow_call",
}
_ACTIONS = {
    "actions/checkout",
    "actions/github-script",
    "actions/upload-artifact",
    "actions/download-artifact",
    "actions/labeler",
}


class Review:
    def __init__(self, limits):
        self.limits = limits
        self.findings, self.reasons, self.observations = [], set(), []
        self.found, self.expr_count, self.step_count = 0, 0, 0
        self.parsed_count = 0
        self.events, self.inputs, self.job_outputs, self.artifacts = set(), {}, {}, {}
        self.finding_keys = set()
        self.active_event = None

    def opened(self, reason):
        self.reasons.add(reason)

    def finding(self, rule, node, flow):
        key = (rule, node.pos, flow.origins, self.active_event)
        if key in self.finding_keys:
            return
        self.finding_keys.add(key)
        self.found += 1
        if len(self.findings) >= self.limits.findings:
            raise OpenInput("finding_budget")
        self.findings.append(
            {
                "rule": rule,
                "status": "FAIL",
                "evidence": "potential_static_flow",
                "sink": {"line": node.line, "column": node.column},
                "event_context": self.active_event,
                "sources": [{"kind": o[0], "line": o[1], "column": o[2]} for o in flow.origins],
                "channels": sorted(flow.channels),
            }
        )

    def observe(self, kind, node):
        if len(self.observations) < self.limits.findings:
            self.observations.append({"kind": kind, "line": node.line, "column": node.column})
        else:
            self.opened("observation_budget")

    def resolve(self, parts, node, env, outputs, output_default, needs):
        path = ".".join(parts)
        origin = ("event_text", *node.pos)
        if path in ("github.ref", "github.ref_name"):
            if self.active_event == "pull_request":
                return Flow(code=True, origins=(("pull_request_merge_ref", *node.pos),))
            if self.active_event in ("pull_request_target", "workflow_run", "schedule"):
                return SAFE
        if path == "github.head_ref" and self.active_event not in (
            "pull_request",
            "pull_request_target",
        ):
            return UNKNOWN
        if path.startswith("github.event.pull_request.") and self.active_event not in (
            "pull_request",
            "pull_request_target",
        ):
            return UNKNOWN
        if path.startswith("github.event.workflow_run.") and self.active_event != "workflow_run":
            return UNKNOWN
        if path == "github.sha" and self.active_event == "pull_request":
            return Flow(code=True, origins=(("pull_request_merge_commit", *node.pos),))
        if path in _ARBITRARY or path in _CODE_REFS:
            return Flow(path in _ARBITRARY, path in _CODE_REFS, origins=(origin,))
        if path in _FIXED:
            return SAFE
        if parts[0] == "secrets":
            return Flow(sensitive=True)
        if parts[0] == "env" and len(parts) == 2:
            flow = env.get(parts[1], env.get("__unknown__", UNKNOWN))
            return flow.via("environment", ("environment_declaration", *node.pos))
        if parts[0] == "steps" and len(parts) == 4 and parts[2] == "outputs":
            default = output_default.get(parts[1], UNKNOWN)
            flow = merge(outputs.get(parts[1], {}).get(parts[3], default), default)
            return flow.via("step_output", ("step_output_reference", *node.pos))
        if parts[0] == "steps" and len(parts) == 3 and parts[2] in ("outcome", "conclusion"):
            return SAFE if parts[1] in output_default else UNKNOWN
        if parts[0] == "needs" and len(parts) == 4 and parts[2] == "outputs":
            flow = (
                self.job_outputs.get(parts[1], {}).get(parts[3], UNKNOWN)
                if parts[1] in needs
                else UNKNOWN
            )
            return flow.via("needs_output", ("job_output_reference", *node.pos))
        if parts[0] == "needs" and len(parts) == 3 and parts[2] == "result":
            return SAFE if parts[1] in needs and parts[1] in self.job_outputs else UNKNOWN
        if parts[0] == "inputs" and len(parts) == 2:
            return self.inputs.get(parts[1], UNKNOWN)
        if path.startswith("github.event.inputs.") and len(parts) == 4:
            return self.inputs.get(parts[-1], UNKNOWN)
        if parts[0] in (
            "github",
            "runner",
            "vars",
            "matrix",
            "strategy",
            "job",
            "inputs",
            "needs",
            "steps",
        ):
            return UNKNOWN
        return UNKNOWN

    def expression(self, text, node, env, outputs, defaults, needs):
        if self.expr_count >= self.limits.expressions:
            raise OpenInput("expression_count_budget")
        self.expr_count += 1
        try:
            ast = expressions.parse(text, self.limits)
            self.parsed_count += 1
            value = expressions.evaluate(
                ast, lambda parts: self.resolve(parts, node, env, outputs, defaults, needs)
            )
            if value.flow.unknown:
                self.opened("unresolved_expression_flow")
            return value
        except OpenInput as error:
            self.opened(str(error))
            return expressions.Value(UNKNOWN)

    def template(self, node, env, outputs, defaults, needs):
        text = scalar(node)
        if text is None:
            return SAFE, []
        substitutions = []
        try:
            for start, end, expression in expressions.fences(text):
                value = self.expression(expression, node, env, outputs, defaults, needs)
                substitutions.append((start, end, value.flow))
        except OpenInput as error:
            self.opened(str(error))
            return merge(UNKNOWN, *(f for _, _, f in substitutions)), substitutions
        return merge(*(f for _, _, f in substitutions)), substitutions

    def environment(self, node, previous, outputs, defaults, needs):
        result = dict(previous)
        if node is None:
            return result
        if node.kind != "map":
            self.opened("dynamic_environment")
            return {"__unknown__": UNKNOWN}
        declared = set()
        spellings = {}
        for key, binding in previous.items():
            if key.startswith("__shell_binding__:"):
                raw_name = key[len("__shell_binding__:") :]
                spellings.setdefault(raw_name.lower(), {})[raw_name] = binding
        for name, value in node.value.items():
            if not _ID.fullmatch(name):
                self.opened("unsupported_environment_name")
                continue
            flow, _ = self.template(value, previous, outputs, defaults, needs)
            other_case = [
                binding
                for spelling, binding in spellings.get(name.lower(), {}).items()
                if spelling != name
            ]
            if other_case:
                self.opened("ambiguous_environment_case")
                flow = merge(flow, *other_case, UNKNOWN)
            if name.lower() in declared:
                self.opened("ambiguous_environment_case")
                flow = merge(flow, result[name.lower()], UNKNOWN)
            declared.add(name.lower())
            result[name.lower()] = flow.via("environment", ("environment_declaration", *value.pos))
            # Shell names are case sensitive on the modeled POSIX runners.
            result["__shell_binding__:" + name] = result[name.lower()]
        return result

    def condition(self, node, env, outputs, defaults, needs):
        if node is None:
            return True
        text = scalar(node).strip()
        if text.lower() in ("true", "false"):
            return text.lower() == "true"
        try:
            items = list(expressions.fences(text))
        except OpenInput as error:
            self.opened(str(error))
            return True
        if len(items) == 1 and items[0][0] == 0 and items[0][1] == len(text):
            value = self.expression(items[0][2], node, env, outputs, defaults, needs)
        else:
            value = self.expression(text, node, env, outputs, defaults, needs)
        if value.known and isinstance(value.literal, bool):
            return value.literal
        self.opened("dynamic_condition_not_proven")
        return True

    def sink(self, node, flow, action=False):
        if flow.arbitrary:
            if "needs_output" in flow.channels:
                rule = "needs_output_to_code"
            elif "step_output" in flow.channels:
                rule = "step_output_to_code"
            elif "environment" in flow.channels:
                rule = "environment_to_code"
            else:
                rule = "expression_to_action_script" if action else "expression_to_run"
            self.finding(rule, node, flow)
        if flow.unknown:
            self.opened("unresolved_code_sink")

    def triggers(self, node):
        if node is None:
            raise OpenInput("missing_event_context")
        if node.kind == "scalar":
            events = [node.value]
        elif node.kind == "seq":
            events = [scalar(n) for n in node.value]
        else:
            events = list(mapping(node))
        if not events or any(e not in _EVENTS for e in events):
            self.opened("unsupported_event_context")
        self.events = set(events)
        if "workflow_call" in self.events:
            self.opened("caller_event_context_missing")
        dispatch = node.get("workflow_dispatch")
        declarations = (
            mapping(dispatch.get("inputs")) if dispatch and dispatch.kind == "map" else {}
        )
        for name, declaration in declarations.items():
            if not _ID.fullmatch(name):
                self.opened("unsupported_input_name")
            fields = mapping(declaration)
            type_name = scalar(fields.get("type"))
            if type_name in ("boolean", "number"):
                flow = SAFE
            elif type_name == "choice":
                options = fields.get("options")
                values = [scalar(n) for n in sequence(options)]
                flow = (
                    SAFE if values and all(_FIXED_CHOICE.fullmatch(v) for v in values) else UNKNOWN
                )
            elif type_name in (None, "string", "environment"):
                flow = Flow(arbitrary=True, origins=(("dispatch_input", *declaration.pos),))
            else:
                flow = UNKNOWN
            if name.lower() in self.inputs:
                self.opened("ambiguous_input_case")
                flow = merge(flow, self.inputs[name.lower()], UNKNOWN)
            self.inputs[name.lower()] = flow

    def permission_context(self, node):
        if node is None:
            return False
        if node.kind == "scalar":
            if node.value == "write-all":
                return True
            if node.value != "read-all":
                self.opened("dynamic_privilege_context")
            return False
        values = [scalar(value) for value in mapping(node).values()]
        if any(value not in ("read", "write", "none") for value in values):
            self.opened("dynamic_privilege_context")
        return "write" in values

    def action(self, node, fields, env, outputs, defaults, needs, workspace, privileged):
        uses_node = fields["uses"]
        uses = scalar(uses_node)
        action, separator, reference = uses.partition("@")
        if not separator or not reference or "${{" in uses or action not in _ACTIONS:
            self.opened("action_body_not_supplied")
            if uses.startswith("./") and workspace.code and privileged:
                self.finding("privileged_workspace_execution", uses_node, workspace)
            return merge(workspace, UNKNOWN), {}, UNKNOWN, UNKNOWN
        with_fields = mapping(fields.get("with"))
        flows = {
            key: self.template(value, env, outputs, defaults, needs)[0]
            for key, value in with_fields.items()
        }
        if action == "actions/checkout":
            code = flows.get("ref", SAFE)
            repository = flows.get("repository", SAFE)
            if "ref" not in with_fields and self.active_event == "pull_request":
                code = merge(
                    code,
                    Flow(code=True, origins=(("pull_request_default_checkout", *uses_node.pos),)),
                )
            if "ref" in with_fields and not flows["ref"].code and not flows["ref"].unknown:
                # Explicit literal refs are caller-maintained code; trust identity OPEN.
                pass
            if "repository" in with_fields and not repository.code and not repository.unknown:
                self.opened("literal_external_repository_trust")
            prior_workspace = workspace
            workspace = merge(code, repository).via(
                "checkout", ("checkout_declaration", *uses_node.pos)
            )
            if scalar(with_fields.get("clean")) not in (None, "true"):
                self.opened("checkout_clean_not_proven")
                workspace = merge(workspace, prior_workspace, UNKNOWN)
            if workspace.code and privileged:
                self.finding("privileged_untrusted_checkout", uses_node, workspace)
            if workspace.unknown:
                self.opened("unresolved_checkout_origin")
            if any(
                k in with_fields
                for k in ("path", "sparse-checkout", "sparse-checkout-cone-mode", "submodules")
            ):
                self.opened("checkout_layout_not_resolved")
                workspace = merge(workspace, UNKNOWN)
            return workspace, {}, SAFE, SAFE
        if action == "actions/github-script":
            script = with_fields.get("script")
            if script is None:
                self.opened("missing_action_script")
            else:
                flow = flows["script"]
                self.sink(script, flow, action=True)
                # A JS program may read process.env, require workspace code, or
                # write output/env files. No JavaScript body parser is claimed.
                self.opened("action_script_body_effects_unknown")
                workspace = merge(workspace, UNKNOWN)
            return workspace, {}, UNKNOWN, UNKNOWN
        if action == "actions/labeler":
            # Built-in model has no user-controlled script parameter. Its body,
            # provenance, configuration and actual API permissions remain OPEN.
            if any(f.arbitrary or f.unknown for f in flows.values()):
                self.opened("labeler_dynamic_inputs")
            return workspace, {}, UNKNOWN, SAFE
        name = scalar(with_fields.get("name"))
        if not name or "${{" in name:
            self.opened("artifact_name_not_resolved")
        if action == "actions/upload-artifact":
            flow = workspace.via("artifact", ("artifact_upload", *uses_node.pos))
            if name and "${{" not in name:
                self.artifacts[name] = merge(self.artifacts.get(name, SAFE), flow)
            self.opened("artifact_payload_not_supplied")
            return workspace, {}, SAFE, SAFE
        external = "run-id" in with_fields or "repository" in with_fields
        if external:
            if self.active_event == "workflow_run":
                downloaded = Flow(
                    code=True,
                    origins=(("external_workflow_artifact", *uses_node.pos),),
                    channels=frozenset({"artifact"}),
                )
            else:
                downloaded = UNKNOWN.via("artifact", ("external_artifact", *uses_node.pos))
            self.opened("external_artifact_origin_not_authenticated")
        else:
            downloaded = self.artifacts.get(name, UNKNOWN).via(
                "artifact", ("artifact_download", *uses_node.pos)
            )
            if name not in self.artifacts:
                self.opened("artifact_producer_not_resolved")
        self.opened("artifact_payload_not_supplied")
        return merge(workspace, downloaded), {}, SAFE, SAFE

    def job(self, node, global_env, needs, privileged):
        fields = mapping(node)
        if any(
            k
            not in {
                "name",
                "needs",
                "if",
                "runs-on",
                "env",
                "defaults",
                "steps",
                "outputs",
                "permissions",
                "timeout-minutes",
                "continue-on-error",
                "strategy",
                "environment",
                "concurrency",
                "container",
                "services",
                "uses",
                "with",
                "secrets",
            }
            for k in fields
        ):
            self.opened("unsupported_job_structure")
        if "uses" in fields:
            self.opened("reusable_workflow_body_not_supplied")
            return {}
        if fields.get("strategy") is not None:
            self.opened("matrix_or_strategy_not_expanded")
        if any(k in fields for k in ("container", "services")):
            self.opened("container_or_service_boundary")
        if fields.get("defaults") is not None:
            self.opened("job_defaults_not_resolved")
        runner = fields.get("runs-on")
        linux_default = (
            runner is not None
            and runner.kind == "scalar"
            and re.fullmatch(r"ubuntu-(?:latest|\d\d\.\d\d(?:-arm)?)", runner.value) is not None
        )
        if not linux_default:
            self.opened("runner_or_default_shell_not_resolved")
        env = self.environment(fields.get("env"), global_env, {}, {}, needs)
        if not self.condition(fields.get("if"), env, {}, {}, needs):
            return {}
        privileged = (
            privileged
            or "environment" in fields
            or self.permission_context(fields.get("permissions"))
        )
        workspace, outputs, defaults = UNKNOWN, {}, {}
        dynamic_env = SAFE
        seen_ids = set()
        for step in sequence(fields.get("steps")):
            if self.step_count >= self.limits.steps:
                raise OpenInput("step_budget")
            self.step_count += 1
            sf = mapping(step)
            if any(
                k
                not in {
                    "id",
                    "name",
                    "if",
                    "uses",
                    "with",
                    "run",
                    "shell",
                    "env",
                    "working-directory",
                    "continue-on-error",
                    "timeout-minutes",
                }
                for k in sf
            ):
                self.opened("unsupported_step_structure")
            base_env = dict(env)
            if dynamic_env.unknown:
                # Unmodeled previous GITHUB_ENV writes can overwrite any key.
                base_env = {key: merge(value, dynamic_env) for key, value in base_env.items()}
                base_env["__unknown__"] = merge(dynamic_env, UNKNOWN)
            step_env = self.environment(sf.get("env"), base_env, outputs, defaults, needs)
            if not self.condition(sf.get("if"), step_env, outputs, defaults, needs):
                continue
            step_privileged = privileged or any(f.sensitive for f in step_env.values())
            step_outputs, default = {}, SAFE
            next_env_default = SAFE
            if ("uses" in sf) == ("run" in sf):
                self.opened("ambiguous_or_missing_step_body")
                workspace, default, next_env_default = merge(workspace, UNKNOWN), UNKNOWN, UNKNOWN
            elif "uses" in sf:
                workspace, step_outputs, default, next_env_default = self.action(
                    step, sf, step_env, outputs, defaults, needs, workspace, step_privileged
                )
            else:
                run = sf["run"]
                flow, substitutions = self.template(run, step_env, outputs, defaults, needs)
                self.sink(run, flow)
                # A secret interpolated directly into run is available to the
                # executed workspace program even without an env declaration.
                run_privileged = step_privileged or flow.sensitive
                shell = scalar(sf.get("shell")) or ("bash" if linux_default else "unknown")
                if shell not in ("bash", "sh") or "working-directory" in sf:
                    self.opened("shell_or_working_directory_not_resolved")
                    result = None
                    default, next_env_default = UNKNOWN, UNKNOWN
                else:
                    result = inspect(scalar(run), substitutions, step_env)
                    if result.unknown:
                        self.opened("shell_effects_not_resolved")
                    if result.isolated:
                        self.observe("environment_used_as_data_in_literal_command", run)
                    for argument in result.code_arguments:
                        if argument.arbitrary:
                            self.finding("environment_to_eval", run, argument)
                        if argument.unknown:
                            self.opened("unresolved_shell_code_argument")
                    if result.workspace_exec and workspace.code and run_privileged:
                        rule = (
                            "artifact_to_execution"
                            if "artifact" in workspace.channels
                            else "privileged_workspace_execution"
                        )
                        self.finding(rule, run, workspace)
                    if result.workspace_exec and workspace.unknown:
                        self.opened("unresolved_workspace_execution")
                    step_outputs, default = result.outputs, result.output_default
                    next_env_default = result.env_default
                    if result.workspace_exec and not workspace.code:
                        self.opened("workspace_program_body_not_supplied")
                    for key, value in result.env_writes.items():
                        written = value.via("environment", ("environment_file_write", *run.pos))
                        env[key.lower()] = written
                        env["__shell_binding__:" + key] = written
                    if result.workspace_exec:
                        default = merge(
                            default,
                            Flow(
                                arbitrary=workspace.code,
                                code=workspace.code,
                                unknown=workspace.unknown,
                                origins=workspace.origins,
                                channels=workspace.channels,
                            ),
                        )
                        next_env_default = merge(next_env_default, default)
                if flow.arbitrary or flow.unknown:
                    # A code interpolation can modify outputs/environment/workspace.
                    default, next_env_default = (
                        merge(default, flow, UNKNOWN),
                        merge(next_env_default, flow, UNKNOWN),
                    )
                    workspace = merge(
                        workspace,
                        Flow(code=flow.arbitrary, unknown=flow.unknown, origins=flow.origins),
                    )
            dynamic_env = merge(dynamic_env, next_env_default)
            step_id = scalar(sf.get("id"))
            if step_id:
                if not _ID.fullmatch(step_id) or step_id.lower() in seen_ids:
                    self.opened("invalid_or_duplicate_step_id")
                else:
                    step_id = step_id.lower()
                    seen_ids.add(step_id)
                    outputs[step_id] = step_outputs
                    defaults[step_id] = default
        exported = {}
        for key, value in mapping(fields.get("outputs")).items():
            exported[key.lower()] = self.template(value, env, outputs, defaults, needs)[0].via(
                "needs_output", ("job_output_declaration", *value.pos)
            )
        return exported

    def run(self, root):
        fields = mapping(root)
        if any(
            k
            not in {
                "name",
                "run-name",
                "on",
                "jobs",
                "env",
                "defaults",
                "permissions",
                "concurrency",
            }
            for k in fields
        ):
            self.opened("unsupported_workflow_structure")
        if fields.get("defaults") is not None:
            self.opened("workflow_defaults_not_resolved")
        self.triggers(fields.get("on"))
        workflow_privilege = self.permission_context(fields.get("permissions"))
        jobs = mapping(fields.get("jobs"))
        if not jobs:
            raise OpenInput("missing_jobs")
        if len(jobs) > self.limits.jobs:
            raise OpenInput("job_budget")
        remaining, dependencies = {}, {}
        for name, node in jobs.items():
            if not _ID.fullmatch(name) or name.lower() in remaining:
                raise OpenInput("invalid_or_duplicate_job_id")
            name = name.lower()
            remaining[name] = node
            need = node.get("needs")
            if need is None:
                dependencies[name] = []
            elif need.kind == "scalar":
                dependencies[name] = [need.value.lower()]
            elif need.kind == "seq":
                dependencies[name] = [scalar(n).lower() for n in need.value]
            else:
                self.opened("dynamic_job_dependency")
                dependencies[name] = ["__unknown__"]
        # Distinct event scenarios prevent merging a PR checkout from one event
        # with default elevated credentials from a different event.
        job_nodes = dict(remaining)
        for event in sorted(self.events & _EVENTS):
            self.active_event = event
            global_env = self.environment(fields.get("env"), {}, {}, {}, [])
            self.job_outputs, self.artifacts = {}, {}
            remaining = dict(job_nodes)
            privileged = workflow_privilege or event in ("pull_request_target", "workflow_run")
            while remaining:
                progressed = False
                for name in list(remaining):
                    needs = dependencies[name]
                    if all(n in self.job_outputs for n in needs):
                        self.job_outputs[name] = self.job(
                            remaining.pop(name), global_env, needs, privileged
                        )
                        progressed = True
                if not progressed:
                    self.opened("missing_or_cyclic_job_dependency")
                    for name, node in remaining.items():
                        self.job_outputs[name] = self.job(node, global_env, [], privileged)
                    break


def review(data, limits=None):
    if not isinstance(data, bytes):
        raise TypeError("expected_bytes")
    if limits is None:
        limits = Limits()
    if not isinstance(limits, Limits):
        raise TypeError("expected_limits")
    engine = Review(limits)
    report = fallback("unreviewed")
    try:
        root, count = parse_yaml(data, limits)
        report["yaml_nodes"] = count
        engine.run(root)
    except OpenInput as error:
        engine.opened(str(error))
    report.update(
        {
            "status": "FAIL" if engine.found else "OPEN" if engine.reasons else "PASS",
            "complete": not engine.reasons,
            "findings": engine.findings,
            "finding_count": engine.found,
            "open_reasons": sorted(engine.reasons),
            "observations": engine.observations,
            "rules": list(RULES),
            "events": sorted(e for e in engine.events if e in _EVENTS),
            "reviewed_steps": engine.step_count,
            "parsed_expressions": engine.parsed_count,
            "attempted_expressions": engine.expr_count,
            "position_unit": "yaml_scalar_start_1_based",
            "input_sha256": hashlib.sha256(data).hexdigest()
            if len(data) <= limits.input_bytes
            else None,
            "input_digest_status": "PASS" if len(data) <= limits.input_bytes else "OPEN",
            "limits": asdict(limits),
        }
    )
    while len(json.dumps(report, sort_keys=True).encode()) > limits.report_bytes:
        report["complete"] = False
        if "report_budget" not in report["open_reasons"]:
            report["open_reasons"].append("report_budget")
        report["status"] = "FAIL" if engine.found else "OPEN"
        if report["observations"]:
            report["observations"] = report["observations"][: len(report["observations"]) // 2]
        elif report["findings"]:
            report["findings"] = report["findings"][: len(report["findings"]) // 2]
        else:
            small = fallback("report_budget")
            small.update(status=report["status"], finding_count=engine.found)
            return small
    return report
