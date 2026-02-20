#!/usr/bin/env python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

import argparse
import json
import re
import sys
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
    "UnmarshalControlFlow",
    "ExternalSymbolResolution",
    "PlatformHelperAvailability",
    "ElfCoreRelocation",
    "ElfSubprogramResolution",
    "ElfLegacyMapLayout",
    "VerificationTimeout",
    "LegacyBccBehavior",
}


def cpp_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def cpp_kind(kind: str | None) -> str:
    if kind is None:
        raise ValueError("Missing required failure kind")
    if kind not in VALID_KINDS:
        raise ValueError(f"Unsupported kind '{kind}'")
    return f"verify_test::VerifyIssueKind::{kind}"


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


def is_load_failure_reason(reason: str | None) -> bool:
    if reason is None:
        return False
    return reason.startswith("Unsupported or invalid CO-RE/BTF relocation data:") or reason.startswith(
        "Subprogram not found:"
    )


def classify_section(obj: dict, section: str, programs: list[dict]) -> tuple[str, str | None, str | None]:
    override = section_override(obj, section)
    if override is not None:
        status = override.get("status")
        kind = override.get("kind")
        reason = override.get("reason")
        if status not in ("pass", "expected_failure", "skip"):
            raise ValueError(f"Unsupported status '{status}' for section '{section}'")
        if status in ("expected_failure", "skip"):
            if not kind:
                raise ValueError(f"Missing kind for section '{section}' with status '{status}'")
            if not reason:
                raise ValueError(f"Missing reason for section '{section}' with status '{status}'")
        return status, kind, reason

    if len(programs) != 1:
        return "pass", None, None

    if any(program.get("invalid", False) for program in programs):
        reason = next((program.get("invalid_reason") for program in programs if program.get("invalid_reason")), None)
        return "skip", "ElfSubprogramResolution", reason or "invalid section in ELF metadata"

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
    if status == "expected_failure":
        return [
            f"// expected failure ({kind}): {reason}",
            f'TEST_SECTION_FAIL("{p}", "{o}", "{s}", {cpp_kind(kind)}, "{reason_text}")',
        ]
    if status == "skip":
        if is_load_failure_reason(reason):
            return [
                f"// expected load failure ({kind}): {reason}",
                f'TEST_SECTION_LOAD_FAIL("{p}", "{o}", "{s}", {cpp_kind(kind)}, "{reason_text}")',
            ]
        return [f'// skipped ({kind}): {reason}', f'TEST_SECTION_SKIP("{p}", "{o}", "{s}", {cpp_kind(kind)}, "{reason_text}")']
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
    if status == "expected_failure":
        return [
            f"// expected failure ({kind}): {reason}",
            f'TEST_PROGRAM_FAIL("{p}", "{o}", "{s}", "{f}", {section_program_count}, {cpp_kind(kind)}, "{reason_text}")',
        ]
    if status == "skip":
        return [f'// skipped ({kind}): {reason}', f'TEST_PROGRAM_SKIP("{p}", "{o}", "{s}", "{f}", {cpp_kind(kind)}, "{reason_text}")']
    raise ValueError(f"Unsupported status '{status}'")


def generate(inventory: dict, project: str) -> str:
    project_entry = inventory.get("projects", {}).get(project)
    if project_entry is None:
        raise ValueError(f"Project '{project}' not found in inventory")

    lines: list[str] = [
        "// Copyright (c) Prevail Verifier contributors.",
        "// SPDX-License-Identifier: MIT",
        "",
        "#include \"test_verify.hpp\"",
        "",
        f"// Generated by scripts/generate_verify_project_tests.py for project '{project}'.",
    ]

    for object_name in sorted(project_entry["objects"].keys()):
        obj = project_entry["objects"][object_name]
        for section_name in sorted(obj["sections"].keys()):
            programs = obj["sections"][section_name]
            if len(programs) == 1:
                status, kind, reason = classify_section(obj, section_name, programs)
                lines.extend(render_test(project, object_name, section_name, status, kind, reason))
                continue

            for program in sorted(programs, key=lambda p: p["function"]):
                function_name = program["function"]
                override = program_override(obj, section_name, function_name)
                if override is not None:
                    status = override.get("status")
                    kind = override.get("kind")
                    reason = override.get("reason")
                    if status not in ("pass", "expected_failure", "skip"):
                        raise ValueError(
                            f"Unsupported status '{status}' for program '{function_name}' in section '{section_name}'"
                        )
                    if status in ("expected_failure", "skip"):
                        if not kind:
                            raise ValueError(
                                f"Missing kind for program '{function_name}' in section '{section_name}' with status '{status}'"
                            )
                        if not reason:
                            raise ValueError(
                                f"Missing reason for program '{function_name}' in section '{section_name}' with status '{status}'"
                            )
                else:
                    status = "pass"
                    kind = None
                    reason = None
                lines.extend(
                    render_program_test(
                        project, object_name, section_name, function_name, len(programs), status, kind, reason
                    )
                )

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
