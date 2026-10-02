"""New finite lexer, precedence parser, and conservative value-flow evaluator."""

import math
import re
from dataclasses import dataclass

from .contracts import SAFE, UNKNOWN, Flow, OpenInput, merge


@dataclass(frozen=True)
class Expr:
    kind: str
    value: object = None
    children: tuple = ()


@dataclass(frozen=True)
class Value:
    flow: Flow = SAFE
    known: bool = False
    literal: object = None


_NUMBER = re.compile(
    r"[+-]?(?:0[xX][0-9a-fA-F]+|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)"
)
_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9-]*")
_PRECEDENCE = {"||": 1, "&&": 2, "==": 3, "!=": 3, "<": 4, ">": 4, "<=": 4, ">=": 4}
_ARITY = {
    "contains": (2, 2),
    "startswith": (2, 2),
    "endswith": (2, 2),
    "format": (2, 64),
    "join": (1, 2),
    "tojson": (1, 1),
    "fromjson": (1, 1),
    "hashfiles": (1, 64),
    "success": (0, 0),
    "failure": (0, 0),
    "cancelled": (0, 0),
    "always": (0, 0),
    "case": (3, 63),
}


def tokens(text, limits):
    if len(text) > limits.expression_chars:
        raise OpenInput("expression_char_budget")
    result, index = [], 0
    while index < len(text):
        c = text[index]
        if c in " \t\r\n":
            index += 1
            continue
        if c == "'":
            index += 1
            value = []
            while index < len(text):
                if text[index] == "'":
                    if index + 1 < len(text) and text[index + 1] == "'":
                        value.append("'")
                        index += 2
                        continue
                    index += 1
                    break
                value.append(text[index])
                index += 1
            else:
                raise OpenInput("invalid_expression")
            result.append(("literal", "".join(value)))
        elif text[index : index + 2] in _PRECEDENCE:
            result.append((text[index : index + 2], None))
            index += 2
        elif c in "()[],.*!<>":
            # Dot before a digit begins a number, otherwise it is member access.
            if c == "." and index + 1 < len(text) and text[index + 1] in "0123456789":
                match = _NUMBER.match(text, index)
                value = float(match.group())
                if not math.isfinite(value):
                    raise OpenInput("nonfinite_expression_number")
                result.append(("literal", value))
                index = match.end()
            else:
                result.append((c, None))
                index += 1
        elif c in "0123456789+-":
            match = _NUMBER.match(text, index)
            if not match:
                raise OpenInput("invalid_expression")
            raw = match.group()
            value = float(int(raw, 16)) if raw.lstrip("+-").lower().startswith("0x") else float(raw)
            if not math.isfinite(value):
                raise OpenInput("nonfinite_expression_number")
            result.append(("literal", value))
            index = match.end()
        else:
            match = _IDENT.match(text, index)
            if not match:
                raise OpenInput("invalid_expression")
            result.append(("ident", match.group().lower()))
            index = match.end()
        if len(result) > limits.expression_tokens:
            raise OpenInput("expression_token_budget")
    return result + [("end", None)]


class Parser:
    def __init__(self, text, limits):
        self.items, self.index, self.limits = tokens(text, limits), 0, limits

    def take(self, expected=None):
        item = self.items[self.index]
        if expected is not None and item[0] != expected:
            raise OpenInput("invalid_expression")
        self.index += 1
        return item

    def expression(self, minimum=0, depth=0):
        if depth >= self.limits.expression_depth:
            raise OpenInput("expression_depth_budget")
        kind, value = self.take()
        if kind == "literal":
            left = Expr("literal", value)
        elif kind == "ident":
            if value in ("true", "false", "null"):
                left = Expr("literal", {"true": True, "false": False, "null": None}[value])
            elif self.items[self.index][0] == "(":
                self.take("(")
                args = []
                if self.items[self.index][0] != ")":
                    while True:
                        args.append(self.expression(depth=depth + 1))
                        if self.items[self.index][0] != ",":
                            break
                        self.take(",")
                self.take(")")
                if value not in _ARITY or not _ARITY[value][0] <= len(args) <= _ARITY[value][1]:
                    raise OpenInput("unsupported_function_or_arity")
                if value == "case" and len(args) % 2 == 0:
                    raise OpenInput("unsupported_function_or_arity")
                left = Expr("call", value, tuple(args))
            else:
                left = Expr("context", (value,))
        elif kind == "!":
            left = Expr("not", children=(self.expression(5, depth + 1),))
        elif kind == "(":
            left = self.expression(depth=depth + 1)
            self.take(")")
        else:
            raise OpenInput("invalid_expression")
        while self.items[self.index][0] in (".", "["):
            access = self.take()[0]
            if access == ".":
                item = self.take()
                if item[0] not in ("ident", "*"):
                    raise OpenInput("invalid_expression")
                member = item[1] if item[0] == "ident" else "*"
            else:
                part = self.expression(depth=depth + 1)
                self.take("]")
                member = (
                    part.value.lower()
                    if part.kind == "literal" and isinstance(part.value, str)
                    else part
                )
            if left.kind == "context" and isinstance(member, str):
                left = Expr("context", left.value + (member,))
            else:
                children = (left,) + ((member,) if isinstance(member, Expr) else ())
                left = Expr("dynamic_access", children=children)
        while _PRECEDENCE.get(self.items[self.index][0], -1) >= minimum:
            operator = self.take()[0]
            right = self.expression(_PRECEDENCE[operator] + 1, depth + 1)
            left = Expr("binary", operator, (left, right))
        return left


def parse(text, limits):
    try:
        parser = Parser(text, limits)
        result = parser.expression()
        parser.take("end")
        return result
    except (IndexError, OverflowError, RecursionError):
        raise OpenInput("invalid_expression") from None


def evaluate(expr, resolve):
    if expr.kind == "literal":
        return Value(known=True, literal=expr.value)
    if expr.kind == "context":
        if "*" in expr.value:
            return Value(merge(resolve(expr.value), UNKNOWN))
        return Value(resolve(expr.value))
    values = [evaluate(child, resolve) for child in expr.children]
    combined = merge(*(v.flow for v in values))
    if expr.kind == "dynamic_access":
        # A computed selector is not itself emitted as the selected value.
        # Preserve the container's flow and leave the unresolved access OPEN.
        return Value(merge(values[0].flow, UNKNOWN))
    if expr.kind == "not":
        return Value(
            Flow(unknown=combined.unknown),
            values[0].known,
            not bool(values[0].literal) if values[0].known else None,
        )
    if expr.kind == "binary":
        left, right = values
        if expr.value in ("&&", "||"):
            if left.known:
                chosen = right if bool(left.literal) == (expr.value == "&&") else left
                return chosen
            # Both can be results under Actions operand-returning semantics.
            return Value(combined)
        # A valid comparison emits a boolean, never its arbitrary operands.
        return Value(Flow(unknown=combined.unknown))
    if expr.kind == "call":
        if expr.value in (
            "contains",
            "startswith",
            "endswith",
            "success",
            "failure",
            "cancelled",
            "always",
        ):
            return Value(Flow(unknown=combined.unknown))
        if expr.value == "hashfiles":
            return Value(Flow(unknown=combined.unknown))
        if expr.value == "case":
            predicates = list(zip(expr.children[::2][:-1], values[::2][:-1]))
            supported = all(
                (v.known and isinstance(v.literal, bool))
                or child.kind == "not"
                or (child.kind == "binary" and child.value not in ("&&", "||"))
                or (
                    child.kind == "call"
                    and child.value
                    in (
                        "contains",
                        "startswith",
                        "endswith",
                        "success",
                        "failure",
                        "cancelled",
                        "always",
                    )
                )
                for child, v in predicates
            )
            uncertain = not supported or any(v.flow.unknown for _, v in predicates)
            return Value(
                merge(
                    *(v.flow for v in values[1::2]), values[-1].flow, UNKNOWN if uncertain else SAFE
                )
            )
        if expr.value == "fromjson":
            return Value(merge(combined, UNKNOWN))
        # format/join/toJSON preserve arbitrary contents; JSON encoding is not
        # shell/JavaScript escaping. We intentionally do not run any formatter.
        return Value(combined)
    return Value(UNKNOWN)


def fences(text):
    """Yield decoded-scalar spans, recognizing escaped single quotes."""
    cursor = 0
    while True:
        start = text.find("${{", cursor)
        if start < 0:
            return
        index, quoted = start + 3, False
        while index < len(text):
            if text[index] == "'":
                if quoted and index + 1 < len(text) and text[index + 1] == "'":
                    index += 2
                    continue
                quoted = not quoted
            elif not quoted and text.startswith("}}", index):
                yield start, index + 2, text[start + 3 : index]
                cursor = index + 2
                break
            index += 1
        else:
            raise OpenInput("unterminated_expression")
