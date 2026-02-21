#!/usr/bin/env python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
from pathlib import Path


PROGRAM_LINE = re.compile(r"^section=(?P<section>\S+) function=(?P<function>\S+)(?: \[invalid: (?P<reason>.*)\])?$")


def is_elf_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def discover_elf_files(samples_root: Path) -> list[Path]:
    elf_files: list[Path] = []
    for entry in samples_root.rglob("*"):
        if entry.is_file() and is_elf_file(entry):
            elf_files.append(entry)
    elf_files.sort()
    return elf_files


def parse_check_output(output_lines: list[str]) -> tuple[dict[str, list[dict[str, str | bool]]], list[str]]:
    sections: dict[str, list[dict[str, str | bool]]] = {}
    diagnostics: list[str] = []

    for line in output_lines:
        text = line.strip()
        if not text:
            continue
        match = PROGRAM_LINE.match(text)
        if match is None:
            diagnostics.append(text)
            continue

        section = match.group("section")
        function = match.group("function")
        reason = match.group("reason")

        program = {"function": function, "invalid": reason is not None}
        if reason:
            program["invalid_reason"] = reason
        sections.setdefault(section, []).append(program)

    for section in sections:
        sections[section].sort(key=lambda p: p["function"])

    diagnostics.sort()
    return sections, diagnostics


def inspect_object(check_bin: Path, root: Path, elf_path: Path, timeout_seconds: int) -> tuple[str, str, dict]:
    rel = elf_path.relative_to(root)
    cmd = [str(check_bin), "-l", str(elf_path)]
    completed = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout_seconds)

    combined_lines = []
    combined_lines.extend(completed.stdout.splitlines())
    combined_lines.extend(completed.stderr.splitlines())
    sections, diagnostics = parse_check_output(combined_lines)

    section_names = sorted(sections.keys())
    program_count = sum(len(programs) for programs in sections.values())

    project = rel.parts[0] if len(rel.parts) >= 2 else "_root"
    object_name = Path(*rel.parts[1:]).as_posix() if len(rel.parts) >= 2 else rel.as_posix()

    return project, object_name, {
        "exit_code": completed.returncode,
        "section_count": len(section_names),
        "program_count": program_count,
        "sections": {name: sections[name] for name in section_names},
        "diagnostics": diagnostics,
    }


def build_inventory(samples_root: Path, check_bin: Path, jobs: int, timeout_seconds: int) -> dict:
    elf_paths = discover_elf_files(samples_root)
    objects_by_project: dict[str, dict[str, dict]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = [executor.submit(inspect_object, check_bin, samples_root, elf_path, timeout_seconds) for elf_path in elf_paths]
        for future in concurrent.futures.as_completed(futures):
            project, object_name, data = future.result()
            project_objects = objects_by_project.setdefault(project, {})
            if object_name in project_objects:
                raise RuntimeError(f"Duplicate object name '{object_name}' in project '{project}'")
            project_objects[object_name] = data

    project_names = sorted(objects_by_project.keys())
    projects = {
        project: {
            "object_count": len(objects_by_project[project]),
            "objects": {name: objects_by_project[project][name] for name in sorted(objects_by_project[project].keys())},
        }
        for project in project_names
    }

    total_objects = sum(project["object_count"] for project in projects.values())
    total_sections = sum(
        obj["section_count"] for project in projects.values() for obj in project["objects"].values()
    )
    total_programs = sum(
        obj["program_count"] for project in projects.values() for obj in project["objects"].values()
    )

    return {
        "schema_version": 1,
        "summary": {
            "object_count": total_objects,
            "section_count": total_sections,
            "program_count": total_programs,
        },
        "projects": projects,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a complete project/object/section/program inventory from ebpf-samples."
    )
    parser.add_argument("--samples-root", default="ebpf-samples", help="Root directory to scan for ELF files.")
    parser.add_argument("--check-bin", default="bin/check", help="Path to prevail check executable.")
    parser.add_argument("--output", default="-", help="Output JSON path, or '-' for stdout.")
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, (os.cpu_count() or 1)),
        help="Number of concurrent check processes.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=60,
        help="Timeout for each `check -l` invocation.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    samples_root = Path(args.samples_root)
    check_bin = Path(args.check_bin)

    if not samples_root.exists():
        print(f"error: samples root not found: {samples_root}", file=sys.stderr)
        return 2
    if not check_bin.exists():
        print(f"error: check binary not found: {check_bin}", file=sys.stderr)
        return 2
    if args.jobs < 1:
        print("error: --jobs must be >= 1", file=sys.stderr)
        return 2
    if args.timeout_seconds < 1:
        print("error: --timeout-seconds must be >= 1", file=sys.stderr)
        return 2

    inventory = build_inventory(samples_root, check_bin, args.jobs, args.timeout_seconds)
    rendered = json.dumps(inventory, indent=2, sort_keys=True)

    if args.output == "-":
        print(rendered)
    else:
        output_path = Path(args.output)
        output_path.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote {output_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
