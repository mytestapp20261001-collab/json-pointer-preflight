#!/usr/bin/env python3
"""Offline, read-only audit. Python 3.12+, standard library only."""
import argparse
import json
import math
import re
import stat
import sys
from decimal import Context, Decimal, InvalidOperation
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 50000
MAX_FINDINGS = 100

class InputError(ValueError):
    """A safe, non-payload-bearing input error code."""

class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid_arguments")

def read_text(path):
    p = Path(path)
    if not stat.S_ISREG(p.stat().st_mode):
        raise InputError("regular_file_required")
    with p.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise InputError("file_size_limit")
    return data.decode("utf-8")

def reject_constant(value):
    raise InputError("non_finite_json_number")

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate_json_member")
        result[key] = value
    return result

def parse_decimal(value):
    # Decimal construction must not inherit a host application's disabled traps.
    return Decimal(value, context=Context(traps=[InvalidOperation]))

def parse_json(text):
    try:
        result = json.loads(text, object_pairs_hook=unique_pairs,
                            parse_float=parse_decimal, parse_constant=reject_constant)
    except InputError:
        raise
    except (ValueError, RecursionError, InvalidOperation):
        raise InputError("invalid_json") from None
    stack, nodes = [(result, 0)], 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if depth > 128 or nodes > 200000:
            raise InputError("json_structure_limit")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return result

class Report:
    def __init__(self, tool):
        self.tool, self.findings, self.count = tool, [], 0
    def add(self, code, **location):
        self.count += 1
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(dict(code=code, **location))
    def finish(self, **summary):
        return {"tool": self.tool, "status": "fail" if self.count else "pass",
                "summary": dict(summary, finding_count=self.count),
                "findings": self.findings,
                "findings_truncated": self.count > len(self.findings)}

def emit_main(run):
    try:
        result = run()
        code = 1 if result["status"] == "fail" else 0
    except InputError as exc:
        result, code = {"tool": TOOL, "status": "error", "error": str(exc)}, 2
    except (OSError, UnicodeError):
        result, code = {"tool": TOOL, "status": "error", "error": "unreadable_utf8_input"}, 2
    except (ValueError, RecursionError, InvalidOperation):
        result, code = {"tool": TOOL, "status": "error", "error": "invalid_input"}, 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False))
    return code

TOOL = "json-pointer-preflight"

def tokens(pointer):
    if not isinstance(pointer, str) or len(pointer) > 16384:
        raise InputError("invalid_pointer")
    if pointer == "":
        return []
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise InputError("invalid_pointer_syntax")
    result = [s.replace("~1", "/").replace("~0", "~") for s in pointer[1:].split("/")]
    if len(result) > 128:
        raise InputError("pointer_depth_limit")
    return result

def audit(document, pointers):
    if not isinstance(pointers, list) or not 1 <= len(pointers) <= 10000:
        raise InputError("pointer_list_required")
    report = Report(TOOL)
    resolved = 0
    for number, pointer in enumerate(pointers, 1):
        try:
            parts = tokens(pointer)
        except InputError as exc:
            report.add(str(exc), pointer=number)
            continue
        current, failed = document, False
        for depth, token in enumerate(parts, 1):
            if isinstance(current, dict):
                if token not in current:
                    report.add("missing_member", pointer=number, segment=depth)
                    failed = True
                    break
                current = current[token]
            elif isinstance(current, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", token):
                    report.add("invalid_array_index", pointer=number, segment=depth)
                    failed = True
                    break
                # Compare digit lengths before conversion to avoid huge integers.
                if len(token) > len(str(len(current))) or int(token) >= len(current):
                    report.add("array_index_out_of_bounds", pointer=number, segment=depth)
                    failed = True
                    break
                current = current[int(token)]
            else:
                report.add("scalar_traversal", pointer=number, segment=depth)
                failed = True
                break
        if not failed:
            resolved += 1
    return report.finish(pointers=len(pointers), resolved=resolved)

def run():
    parser = Parser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("--pointers", required=True, help="JSON array of plain RFC 6901 strings")
    args = parser.parse_args()
    return audit(parse_json(read_text(args.input)), parse_json(read_text(args.pointers)))

if __name__ == "__main__":
    sys.exit(emit_main(run))
