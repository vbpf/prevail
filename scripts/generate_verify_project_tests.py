#!/usr/bin/env python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

import argparse
import json
import re
import sys
import textwrap
from collections import defaultdict
from pathlib import Path

VALID_KINDS = {
    "VerifierTypeTracking",
    "VerifierBoundsTracking",
    "VerifierStackInitialization",
    "VerifierPointerArithmetic",
    "VerifierMapTyping",
    "VerifierNullability",
    "VerifierContextModeling",
    "VerifierRecursionModeling",
    "VerificationTimeout",
    "LegacyBccBehavior",
}

KIND_ORDER = [
    "VerifierTypeTracking",
    "VerifierBoundsTracking",
    "VerifierStackInitialization",
    "VerifierPointerArithmetic",
    "VerifierMapTyping",
    "VerifierNullability",
    "VerifierContextModeling",
    "VerifierRecursionModeling",
    "VerificationTimeout",
    "LegacyBccBehavior",
]

KIND_GUIDANCE = {
    "VerifierTypeTracking": {
        "root": (
            "State refinement loses precise register type information across specific control-flow merges, "
            "so a pointer or scalar register is later treated as an incompatible type."
        ),
        "fix": (
            "Improve type-domain join or widen logic for pointer classes and preserve key path constraints "
            "through merges. Start from the first failing instruction and inspect predecessor states."
        ),
    },
    "VerifierBoundsTracking": {
        "root": (
            "Numeric range reasoning is too coarse for dependent bounds, so safe accesses fail range checks "
            "(packet size, stack window, map value window)."
        ),
        "fix": (
            "Strengthen interval propagation for correlated predicates and arithmetic-derived offsets, and keep "
            "relation information across branches where possible."
        ),
    },
    "VerifierStackInitialization": {
        "root": (
            "Stack byte initialization tracking misses writes or invalidates facts too aggressively, so reads are "
            "reported as non-numeric or uninitialized."
        ),
        "fix": (
            "Tighten per-byte initialization transfer functions and join behavior for stack slots touched through "
            "aliases and conditional writes."
        ),
    },
    "VerifierPointerArithmetic": {
        "root": (
            "Pointer arithmetic rules are stricter than required for this pattern, rejecting arithmetic that should "
            "remain safely typed."
        ),
        "fix": (
            "Refine pointer-plus-scalar typing rules and preserve provenance when arithmetic stays within verified "
            "bounds."
        ),
    },
    "VerifierMapTyping": {
        "root": (
            "Map key or value region typing cannot prove scalar compatibility for helper arguments in these flows."
        ),
        "fix": (
            "Improve map region typing and value or key scalarization so helper argument checks can recover precise "
            "numeric facts."
        ),
    },
    "VerifierNullability": {
        "root": (
            "Null-state tracking is conservative across paths, so values proven non-null on one path are reintroduced "
            "as maybe-null later."
        ),
        "fix": (
            "Refine nullability join rules and path-sensitive implication handling for pointer checks before access."
        ),
    },
    "VerifierContextModeling": {
        "root": (
            "Platform context model does not expose offset semantics expected by the program, so accesses are "
            "rejected."
        ),
        "fix": "Extend context layout and offset modeling for the relevant program type.",
    },
    "VerifierRecursionModeling": {
        "root": (
            "Call-graph handling flags recursion in patterns that should be accepted after proper subprogram "
            "modeling."
        ),
        "fix": (
            "Adjust call-graph expansion and recursion detection to distinguish legal call structure from true "
            "illegal recursion."
        ),
    },
    "VerificationTimeout": {
        "root": "Analysis does not converge in configured time on this workload.",
        "fix": (
            "Profile hot control-flow regions and tighten widening or narrowing strategy while preserving soundness."
        ),
    },
    "LegacyBccBehavior": {
        "root": "Known historical mismatch in specific BCC sample behavior relative to current verifier model.",
        "fix": (
            "Re-validate against intended kernel semantics and update either model assumptions or sample expectation."
        ),
    },
}


def cpp_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def cpp_kind(kind: str | None) -> str:
    if kind is None:
        raise ValueError("Missing required failure kind")
    if kind not in VALID_KINDS:
        raise ValueError(f"Unsupported kind '{kind}'")
    return f"verify_test::VerifyIssueKind::{kind}"


def require_nonpass_kind(status: str, kind: str | None, target: str) -> None:
    if kind is None:
        raise ValueError(f"Missing failure kind for {target}")
    if kind not in VALID_KINDS:
        raise ValueError(f"Unsupported kind '{kind}' for {target}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate src/test/test_verify_<project>.cpp from test-data/elf_inventory.json."
    )
    parser.add_argument("--inventory", default="test-data/elf_inventory.json", help="Inventory JSON path.")
    parser.add_argument("--project", help="Project name under projects in inventory JSON.")
    parser.add_argument("--output", help="Output C++ file path.")
    parser.add_argument("--all", action="store_true", help="Generate files for all projects.")
    parser.add_argument("--output-dir", default="src/test", help="Output directory when --all is used.")
    return parser.parse_args()


def section_override(obj: dict, section: str) -> dict | None:
    return obj.get("test_overrides", {}).get("sections", {}).get(section)


def program_override(obj: dict, section: str, function_name: str) -> dict | None:
    return obj.get("test_overrides", {}).get("programs", {}).get(section, {}).get(function_name)


def wrap_comment(
    text: str, prefix: str = "// ", width: int = 118, continuation_prefix: str | None = None
) -> list[str]:
    continuation = continuation_prefix or prefix
    if not text:
        return [prefix.rstrip()]

    lines: list[str] = []
    first_line = True
    for paragraph in text.splitlines():
        if not paragraph:
            lines.append((prefix if first_line else continuation).rstrip())
            first_line = False
            continue

        paragraph_prefix = prefix if first_line else continuation
        wrapped = textwrap.wrap(
            paragraph,
            width=width - len(paragraph_prefix),
            break_long_words=False,
            break_on_hyphens=False,
        )
        for wrapped_line in wrapped:
            lines.append((prefix if first_line else continuation) + wrapped_line)
            first_line = False

    return lines if lines else [prefix.rstrip()]


def wrap_labeled_comment(label: str, text: str, prefix: str = "//   ", width: int = 118) -> list[str]:
    first_prefix = f"{prefix}{label}: "
    continuation_prefix = f"{prefix}{' ' * (len(label) + 2)}"
    return wrap_comment(text, prefix=first_prefix, continuation_prefix=continuation_prefix, width=width)


def split_reason(reason: str | None) -> tuple[str, str]:
    if not reason:
        return "No reason provided.", "n/a"
    marker = "Diagnostic:"
    index = reason.find(marker)
    if index == -1:
        return reason.strip(), "n/a"
    details = reason[:index].strip()
    diagnostic = reason[index + len(marker) :].strip()
    return details or "No reason provided.", diagnostic or "n/a"


def render_reason_comment(label: str, kind: str | None, reason: str | None) -> list[str]:
    reason_text, diagnostic = split_reason(reason)
    if diagnostic != "n/a":
        return [f"// {label} ({kind}):", *wrap_labeled_comment("diagnostic", diagnostic)]
    return [f"// {label} ({kind}):", *wrap_labeled_comment("note", reason_text)]


def classify_section(obj: dict, section: str, programs: list[dict]) -> tuple[str, str | None, str | None]:
    override = section_override(obj, section)
    if override is not None:
        status = override.get("status")
        kind = override.get("kind")
        reason = override.get("reason")
        if status not in ("pass", "reject", "reject_load", "expected_failure", "skip"):
            raise ValueError(f"Unsupported status '{status}' for section '{section}'")
        if status in ("expected_failure", "skip"):
            require_nonpass_kind(status, kind, f"section '{section}'")
            if not reason:
                raise ValueError(f"Missing reason for section '{section}' with status '{status}'")
        return status, kind, reason

    if len(programs) != 1:
        return "pass", None, None

    return "pass", None, None


def render_test(
    project: str, object_name: str, section_name: str, status: str, kind: str | None, reason: str | None
) -> list[str]:
    p = cpp_string(project)
    o = cpp_string(object_name)
    s = cpp_string(section_name)
    reason_text = cpp_string(reason or "")

    if status == "pass":
        return [f'TEST_SECTION("{p}", "{o}", "{s}")']
    if status == "reject":
        return [f'TEST_SECTION_REJECT("{p}", "{o}", "{s}")']
    if status == "reject_load":
        return [f'TEST_SECTION_REJECT_LOAD("{p}", "{o}", "{s}")']
    if status == "expected_failure":
        return [
            *render_reason_comment("expected failure", kind, reason),
            f'TEST_SECTION_FAIL("{p}", "{o}", "{s}", {cpp_kind(kind)}, "{reason_text}")',
        ]
    if status == "skip":
        return [
            *render_reason_comment("skipped", kind, reason),
            f'TEST_SECTION_SKIP("{p}", "{o}", "{s}", {cpp_kind(kind)}, "{reason_text}")',
        ]
    raise ValueError(f"Unsupported status '{status}'")


def render_program_test(
    project: str,
    object_name: str,
    section_name: str,
    function_name: str,
    section_program_count: int,
    status: str,
    kind: str | None,
    reason: str | None,
) -> list[str]:
    p = cpp_string(project)
    o = cpp_string(object_name)
    s = cpp_string(section_name)
    f = cpp_string(function_name)
    reason_text = cpp_string(reason or "")

    if status == "pass":
        return [f'TEST_PROGRAM("{p}", "{o}", "{s}", "{f}", {section_program_count})']
    if status == "reject":
        return [f'TEST_PROGRAM_REJECT("{p}", "{o}", "{s}", "{f}", {section_program_count})']
    if status == "reject_load":
        raise ValueError(
            f"Program-level reject_load is not supported for {project}/{object_name} {section_name}::{function_name}"
        )
    if status == "expected_failure":
        return [
            *render_reason_comment("expected failure", kind, reason),
            f'TEST_PROGRAM_FAIL("{p}", "{o}", "{s}", "{f}", {section_program_count}, {cpp_kind(kind)}, "{reason_text}")',
        ]
    if status == "skip":
        return [
            *render_reason_comment("skipped", kind, reason),
            f'TEST_PROGRAM_SKIP("{p}", "{o}", "{s}", "{f}", {cpp_kind(kind)}, "{reason_text}")',
        ]
    raise ValueError(f"Unsupported status '{status}'")


def generate(inventory: dict, project: str) -> str:
    project_entry = inventory.get("projects", {}).get(project)
    if project_entry is None:
        raise ValueError(f"Project '{project}' not found in inventory")

    lines: list[str] = [
        "// Copyright (c) Prevail Verifier contributors.",
        "// SPDX-License-Identifier: MIT",
        "",
        '#include "test_verify.hpp"',
        "",
        f"// Generated by scripts/generate_verify_project_tests.py for project '{project}'.",
    ]
    pass_lines: list[str] = []
    grouped_nonpass: dict[str, list[dict]] = defaultdict(list)

    def append_entry(
        status: str,
        kind: str | None,
        reason: str | None,
        body_lines: list[str],
        object_name: str,
        section_name: str,
        function_name: str | None = None,
    ) -> None:
        if status in ("pass", "reject", "reject_load"):
            pass_lines.extend(body_lines)
            return
        require_nonpass_kind(status, kind, f"{project}/{object_name} {section_name}")
        grouped_nonpass[kind].append(
            {
                "status": status,
                "reason": reason or "",
                "diagnostic": split_reason(reason)[1],
                "object_name": object_name,
                "section_name": section_name,
                "function_name": function_name,
                "lines": body_lines,
            }
        )

    for object_name in sorted(project_entry["objects"].keys()):
        obj = project_entry["objects"][object_name]
        for section_name in sorted(obj["sections"].keys()):
            programs = obj["sections"][section_name]
            if len(programs) == 1:
                status, kind, reason = classify_section(obj, section_name, programs)
                append_entry(
                    status,
                    kind,
                    reason,
                    render_test(project, object_name, section_name, status, kind, reason),
                    object_name,
                    section_name,
                )
                continue

            for program in sorted(programs, key=lambda p: p["function"]):
                function_name = program["function"]
                override = program_override(obj, section_name, function_name)
                if override is not None:
                    status = override.get("status")
                    kind = override.get("kind")
                    reason = override.get("reason")
                    if status not in ("pass", "reject", "reject_load", "expected_failure", "skip"):
                        raise ValueError(
                            f"Unsupported status '{status}' for program '{function_name}' in section '{section_name}'"
                        )
                    if status in ("expected_failure", "skip"):
                        require_nonpass_kind(
                            status, kind, f"program '{function_name}' in section '{section_name}'"
                        )
                        if not reason:
                            raise ValueError(
                                f"Missing reason for program '{function_name}' in section '{section_name}' with status '{status}'"
                            )
                else:
                    status = "pass"
                    kind = None
                    reason = None
                append_entry(
                    status,
                    kind,
                    reason,
                    render_program_test(
                        project, object_name, section_name, function_name, len(programs), status, kind, reason
                    ),
                    object_name,
                    section_name,
                    function_name,
                )

    lines.extend(pass_lines)

    kind_order_index = {kind: index for index, kind in enumerate(KIND_ORDER)}
    sorted_kinds = sorted(grouped_nonpass, key=lambda name: (kind_order_index.get(name, len(KIND_ORDER)), name))
    for kind in sorted_kinds:
        entries = grouped_nonpass[kind]
        guidance = KIND_GUIDANCE.get(kind, {"root": "Root cause is not yet documented.", "fix": "Fix direction pending."})
        expected_failure_count = sum(1 for entry in entries if entry["status"] == "expected_failure")
        skip_count = sum(1 for entry in entries if entry["status"] == "skip")
        example = entries[0]
        function_suffix = f"::{example['function_name']}" if example["function_name"] else ""
        example_target = f"{project}/{example['object_name']} {example['section_name']}{function_suffix}"

        lines.extend(
            [
                "",
                "// ===========================================================================",
                f"// Failure Cause Group: {kind}",
                f"// Group size: {len(entries)} tests ({expected_failure_count} expected_failure, {skip_count} skip).",
                "// Root cause:",
                *wrap_comment(guidance["root"], prefix="//   "),
                "// Representative example:",
                *wrap_labeled_comment("test", example_target),
                *wrap_labeled_comment("diagnostic", example["diagnostic"]),
                "// Addressing direction:",
                *wrap_comment(guidance["fix"], prefix="//   "),
                "// ===========================================================================",
            ]
        )
        for entry in entries:
            lines.extend(entry["lines"])

    return "\n".join(lines)


def project_to_filename(project: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", project).strip("_")
    return f"test_verify_{normalized}.cpp"


def main() -> int:
    args = parse_args()
    inventory_path = Path(args.inventory)

    if not inventory_path.exists():
        print(f"error: inventory not found: {inventory_path}", file=sys.stderr)
        return 2

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))

    if args.all:
        if args.project or args.output:
            print("error: --all cannot be combined with --project/--output", file=sys.stderr)
            return 2
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        for project in sorted(inventory.get("projects", {}).keys()):
            rendered = generate(inventory, project)
            output_path = output_dir / project_to_filename(project)
            output_path.write_text(rendered + "\n", encoding="utf-8")
            print(f"Wrote {output_path}", file=sys.stderr)
        return 0

    if not args.project or not args.output:
        print("error: --project and --output are required unless --all is used", file=sys.stderr)
        return 2

    output_path = Path(args.output)
    rendered = generate(inventory, args.project)
    output_path.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
