"""Finite analysis contracts; values and names never enter public evidence."""

from dataclasses import dataclass, fields


class OpenInput(ValueError):
    """An unsupported or malformed input, with a fixed public reason."""


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 1024 * 1024
    yaml_depth: int = 32
    yaml_nodes: int = 20000
    scalar_chars: int = 65536
    jobs: int = 128
    steps: int = 2048
    expression_chars: int = 8192
    expression_tokens: int = 512
    expression_depth: int = 32
    expressions: int = 8192
    findings: int = 1024
    report_bytes: int = 1024 * 1024

    def __post_init__(self):
        for f in fields(self):
            value = getattr(self, f.name)
            if type(value) is not int or value < 1 or value > f.default:
                raise ValueError("invalid_limits")
        if self.yaml_depth > 64 or self.expression_depth > 64:
            raise ValueError("invalid_limits")
        if self.report_bytes < 2048:
            raise ValueError("invalid_limits")


@dataclass(frozen=True)
class Flow:
    arbitrary: bool = False
    code: bool = False
    unknown: bool = False
    sensitive: bool = False
    origins: tuple = ()
    channels: frozenset = frozenset()

    def via(self, channel, origin=None):
        origins = self.origins + ((origin,) if origin else ())
        return Flow(
            self.arbitrary,
            self.code,
            self.unknown,
            self.sensitive,
            tuple(dict.fromkeys(origins))[-16:],
            self.channels | {channel},
        )


SAFE = Flow()
UNKNOWN = Flow(unknown=True)


def merge(*flows):
    return Flow(
        any(f.arbitrary for f in flows),
        any(f.code for f in flows),
        any(f.unknown for f in flows),
        any(f.sensitive for f in flows),
        tuple(dict.fromkeys(o for f in flows for o in f.origins))[-16:],
        frozenset(c for f in flows for c in f.channels),
    )


def fallback(reason):
    return {
        "schema_version": 1,
        "rule_contract": "ctbr-1",
        "status": "OPEN",
        "complete": False,
        "findings": [],
        "open_reasons": [reason],
        "actual_execution": "OPEN",
        "source_authenticity": "OPEN",
        "credential_availability": "OPEN",
        "cvp_eligibility": "OPEN",
        "permission_policy_checked": False,
        "action_pin_policy_checked": False,
        "secret_values_checked": False,
    }
