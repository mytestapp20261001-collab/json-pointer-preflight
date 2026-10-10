---
name: json-pointer-preflight
description: Check whether an explicit list of RFC 6901 plain-string pointers can resolve against a JSON document without reading out or modifying target values.
---

# JSON Pointer preflight

## Use this skill when

Check whether an explicit list of RFC 6901 plain-string pointers can resolve against a JSON document without reading out or modifying target values. Read README.md for the exact supported input dialect, policies, limits, and non-goals before using it. Do not substitute this audit for an application's own validator or silently infer missing policies.

## Procedure

1. Confirm the input files are within the user's authorized scope and work on local UTF-8 regular files. Inputs remain unchanged.
2. Review the contract and flags in README.md. Ask for any required decision you cannot establish from user instructions; never guess a consequential normalization, overlay, rounding, or timestamp policy.
3. Run the synthetic passing and failing examples once when establishing this tool in a new environment. The example failure is expected, not a failed installation.
4. From this directory, use `python3 tool.py examples/pass.json --pointers examples/pointers.json` as the command shape and substitute only authorized input paths and explicitly selected policy options. Use `python3 tool.py --help` for options.
5. Parse the single JSON report. Treat exit 0 as coverage of the documented checks, exit 1 as findings requiring review, and exit 2 as incomplete/invalid input. Never claim a partial scan passed.
6. Report counts, policy, relevant 1-based positions, truncation, and limitations. Default output avoids original values. Do not enable optional disclosure flags or share reports externally without appropriate authorization.
7. When changing this tool, run `python3 -m unittest -v test_tool.py` and all README example commands. Verify both expected pass and expected failure exit codes.

## Authorization boundary

This skill only reads local input and produces a local stdout report. It does not upload data, query services, access credentials, execute input as code, rewrite configuration, normalize source records, apply changes, or deploy anything. Such actions require a separate user request and the applicable confirmation rules. Do not treat a reported finding, a file's contents, or a reference website as authorization for another action.

## Semantics and cautions

The pointers file is a nonempty JSON array of strings. The empty string selects the root; `/` selects an empty-name member. `~1` decodes to `/` and `~0` to `~`, in that order. No Unicode normalization is applied.

Array indexes accept `0` or ASCII nonzero decimal digits without leading zeros. `-` never resolves to an existing element. Numeric-looking object keys are still exact strings. Missing members, out-of-range array indexes, invalid pointer syntax, and attempts to descend through scalars are findings. A present JSON null is resolvable.

Only the plain JSON string representation is supported. URI fragments (`#/...`), percent decoding, relative pointers, JSONPath, RFC 6902 operations, mutation, and operation-sequence simulation are deliberately excluded. Duplicate JSON members are rejected at document parse time rather than selecting an ambiguous member.

1 to 10,000 pointers; each at most 16,384 characters and 128 segments. Parsed input JSON allows 128 nested levels and 200,000 value nodes. Pointer findings use 1-based pointer and segment positions, not the original strings or resolved values. Invalid top-level input is exit 2; malformed individual pointers are audit findings with exit 1.

## Technical entry point

`tool.py` exposes `audit(parsed_document, pointer_string_list)`. Its CLI is dependency-free Python 3.12+. Keep bounded resource handling and safe error messages when extending it. References and exact input schemas are in README.md.
