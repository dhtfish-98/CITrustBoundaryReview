"""Local file to one sanitized JSON report; no workflow operations."""

import argparse
import json
from dataclasses import replace

from .contracts import Limits, OpenInput, fallback
from .input import read_local
from .review import review


def emit(report):
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))


class Parser(argparse.ArgumentParser):
    def error(self, message):
        emit(fallback("invalid_arguments"))
        raise SystemExit(2)


def main(argv=None):
    parser = Parser(description="Review one caller-authorized local workflow without executing it.")
    parser.add_argument("workflow")
    parser.add_argument("--max-input-bytes", type=int, default=Limits.input_bytes)
    options = parser.parse_args(argv)
    try:
        limits = replace(Limits(), input_bytes=options.max_input_bytes)
        report = review(read_local(options.workflow, limits), limits)
    except OpenInput as error:
        report = fallback(str(error))
    except (ValueError, TypeError):
        report = fallback("invalid_limits")
    emit(report)
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]
