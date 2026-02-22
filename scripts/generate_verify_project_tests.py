#!/usr/bin/env python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

import argparse
import json
import re
import sys
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


MAX_LINE = 120


def render_reason_comment(reason: str | None) -> list[str]:
    """Emit a short one-line comment with the reason, if present."""
    if not reason:
        return []
    return [f"// {reason}"]


def wrap_macro(macro: str, args: list[str]) -> str:
    """Format a macro call, wrapping to multiple lines if it exceeds MAX_LINE."""
    one_line = f'{macro}({", ".join(args)})'
    if len(one_line) <= MAX_LINE:
        return one_line
    indent = " " * (len(macro) + 1)
    lines = [f"{macro}({args[0]},"]
    for i, arg in enumerate(args[1:], 1):
        suffix = ")" if i == len(args) - 1 else ","
        lines.append(f"{indent}{arg}{suffix}")
    return "\n".join(lines)


def render_test(
    project: str, object_name: str, section_name: str, status: str, kind: str | None, reason: str | None
) -> list[str]:
    p = cpp_string(project)
    o = cpp_string(object_name)
    s = cpp_string(section_name)

    if status == "pass":
        return [wrap_macro("TEST_SECTION", [f'"{p}"', f'"{o}"', f'"{s}"'])]
    if status == "reject":
        return [wrap_macro("TEST_SECTION_REJECT", [f'"{p}"', f'"{o}"', f'"{s}"'])]
    if status == "reject_load":
        return [wrap_macro("TEST_SECTION_REJECT_LOAD", [f'"{p}"', f'"{o}"', f'"{s}"'])]
    if status == "expected_failure":
        return [
            *render_reason_comment(reason),
            wrap_macro("TEST_SECTION_FAIL", [f'"{p}"', f'"{o}"', f'"{s}"', cpp_kind(kind)]),
        ]
    if status == "skip":
        return [
            *render_reason_comment(reason),
            wrap_macro("TEST_SECTION_SKIP", [f'"{p}"', f'"{o}"', f'"{s}"', cpp_kind(kind)]),
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

    args_base = [f'"{p}"', f'"{o}"', f'"{s}"', f'"{f}"']
    if status == "pass":
        return [wrap_macro("TEST_PROGRAM", [*args_base, str(section_program_count)])]
    if status == "reject":
        return [wrap_macro("TEST_PROGRAM_REJECT", [*args_base, str(section_program_count)])]
    if status == "reject_load":
        raise ValueError(
            f"Program-level reject_load is not supported for {project}/{object_name} {section_name}::{function_name}"
        )
    if status == "expected_failure":
        return [
            *render_reason_comment(reason),
            wrap_macro("TEST_PROGRAM_FAIL", [*args_base, str(section_program_count), cpp_kind(kind)]),
        ]
    if status == "skip":
        return [
            *render_reason_comment(reason),
            wrap_macro("TEST_PROGRAM_SKIP", [*args_base, cpp_kind(kind)]),
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
        lines.append("")
        lines.append(f"// {kind}:")
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
