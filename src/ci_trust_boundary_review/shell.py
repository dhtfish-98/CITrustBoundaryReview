"""Literal shell-command subset, using shlex without executing commands."""

import re
import shlex
from dataclasses import dataclass, field

from .contracts import SAFE, UNKNOWN, merge


_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z_0-9]*)\}|([A-Za-z_][A-Za-z_0-9]*))")
_KEY = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")


@dataclass
class ShellResult:
    outputs: dict = field(default_factory=dict)
    env_writes: dict = field(default_factory=dict)
    output_default: object = SAFE
    env_default: object = SAFE
    code_arguments: list = field(default_factory=list)
    workspace_exec: bool = False
    unknown: bool = False
    isolated: bool = False


def inspect(text, substitutions, environment):
    result = ShellResult()
    masked, cursor, placeholders = [], 0, {}
    for number, (start, end, flow) in enumerate(substitutions):
        token = f"__CTBR_EXPR_{number}__"
        # A source could already contain our marker. Ambiguity never becomes safe.
        if token in text:
            result.unknown = True
        masked.extend([text[cursor:start], token])
        placeholders[token] = flow
        cursor = end
    masked.append(text[cursor:])
    script = "".join(masked)

    def value_flow(value):
        flows = [flow for marker, flow in placeholders.items() if marker in value]
        for match in _VARIABLE.finditer(value):
            name = match[1] or match[2]
            if name not in ("GITHUB_ENV", "GITHUB_OUTPUT"):
                flows.append(
                    environment.get(
                        "__shell_binding__:" + name, environment.get("__unknown__", UNKNOWN)
                    )
                )
        if "$(" in value or "`" in value or "${" in _VARIABLE.sub("", value):
            flows.append(UNKNOWN)
        return merge(*flows)

    for line in script.splitlines():
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            words = list(lexer)
        except ValueError:
            result.unknown = True
            continue
        if not words:
            continue
        command = words[0]
        if command not in ("echo", "printf") and any(
            "GITHUB_OUTPUT" in w or "GITHUB_ENV" in w for w in words
        ):
            result.unknown = True
        if (
            any(w in (";", "&&", "||", "|", "&", "<<", "<<<") for w in words)
            or "$(" in line
            or "`" in line
            or line.endswith("\\")
        ):
            result.unknown = True
        if command in ("if", "then", "fi", "for", "while", "case", "function", "{", "}"):
            result.unknown = True
        if _KEY.fullmatch(command.split("=", 1)[0]) and "=" in command:
            # Assignment/expansion order and command prefixes are outside subset.
            result.unknown = True
        # Literal relative scripts and package build commands consume workspace code.
        if command.startswith(("./", "../")) or command in (
            "make",
            "npm",
            "npx",
            "yarn",
            "pnpm",
            "mvn",
            "gradle",
            "./gradlew",
        ):
            result.workspace_exec = True
        if command in ("source", "."):
            result.workspace_exec = True
        if command in ("bash", "sh", "python", "python3", "node", "ruby", "perl"):
            if len(words) > 1 and words[1] in ("-c", "-e", "--eval"):
                result.code_arguments.append(value_flow(" ".join(words[2:])))
            elif len(words) > 1 and not words[1].startswith("-"):
                result.workspace_exec = True
            else:
                result.unknown = True
        if command == "eval":
            result.code_arguments.append(value_flow(" ".join(words[1:])))
        if command.startswith("$") or "__CTBR_EXPR_" in command:
            result.code_arguments.append(value_flow(command))
        if command in ("echo", "printf"):
            if ">>" in words:
                redirect = words.index(">>")
                target = words[redirect + 1 :] if redirect + 1 < len(words) else []
                if len(target) == 1 and target[0] in (
                    "$GITHUB_OUTPUT",
                    "${GITHUB_OUTPUT}",
                    "$GITHUB_ENV",
                    "${GITHUB_ENV}",
                ):
                    payload = None
                    if command == "echo" and redirect == 2:
                        payload = words[1]
                    if command == "printf" and redirect == 3 and words[1] in ("%s\\n", "%s\n"):
                        payload = words[2]
                    if payload and "=" in payload and _KEY.fullmatch(payload.split("=", 1)[0]):
                        name, value = payload.split("=", 1)
                        flow = value_flow(value)
                        if target[0] in ("$GITHUB_OUTPUT", "${GITHUB_OUTPUT}"):
                            result.outputs[name.lower()] = flow
                            if flow.arbitrary or flow.unknown:
                                # Raw newlines can add records with other names.
                                result.output_default = merge(result.output_default, flow, UNKNOWN)
                                result.unknown = True
                        else:
                            result.env_writes[name] = flow
                            if flow.arbitrary or flow.unknown:
                                result.env_default = merge(result.env_default, flow, UNKNOWN)
                                result.unknown = True
                    else:
                        result.unknown = True
                else:
                    result.unknown = True
            elif not any(w in (">", "<") for w in words):
                flow = value_flow(" ".join(words[1:]))
                if flow.arbitrary and not flow.unknown:
                    # Evidence of data use within this literal command only.
                    result.isolated = True
            else:
                result.unknown = True
        elif command not in (
            "eval",
            "bash",
            "sh",
            "python",
            "python3",
            "node",
            "ruby",
            "perl",
            "true",
            "false",
            "exit",
            "pwd",
            "ls",
            "cat",
            "test",
            "[",
            "make",
            "npm",
            "npx",
            "yarn",
            "pnpm",
            "mvn",
            "gradle",
            "source",
            ".",
        ) and not command.startswith(("./", "../")):
            # Unknown executable could interpret arguments, write environment files,
            # or produce outputs. No guesses about uninspected executable bodies.
            result.unknown = True
        if command == "cat" and any("GITHUB_OUTPUT" in w or "GITHUB_ENV" in w for w in words):
            result.unknown = True
    if result.workspace_exec or result.unknown:
        result.output_default = merge(result.output_default, UNKNOWN)
        result.env_default = merge(result.env_default, UNKNOWN)
    return result
