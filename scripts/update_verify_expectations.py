#!/usr/bin/env python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Refresh section-level verify expectations in test-data/elf_inventory.json using bin/check."
    )
    parser.add_argument("--inventory", default="test-data/elf_inventory.json", help="Inventory JSON path.")
    parser.add_argument("--samples-root", default="ebpf-samples", help="Path to samples root.")
    parser.add_argument("--check-bin", default="bin/check", help="Path to check executable.")
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, (os.cpu_count() or 1)),
        help="Number of concurrent check invocations.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=20, help="Per-section check timeout.")
    return parser.parse_args()


def get_override(obj: dict, section: str) -> dict | None:
    return obj.get("test_overrides", {}).get("sections", {}).get(section)


def classify_from_inventory(programs: list[dict]) -> tuple[str, str] | None:
    if len(programs) != 1:
        return "skip", f"multi-program section ({len(programs)} programs)"

    invalid_reason = next((p.get("invalid_reason") for p in programs if p.get("invalid_reason")), None)
    if any(p.get("invalid", False) for p in programs):
        return "skip", invalid_reason or "invalid section in ELF metadata"

    return None


def run_check(check_bin: Path, object_path: Path, section: str, timeout_seconds: int) -> tuple[str, str]:
    try:
        completed = subprocess.run(
            [str(check_bin), str(object_path), section],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return "skip", f"verification timed out after {timeout_seconds}s"

    if completed.returncode == 0:
        return "pass", ""

    diagnostics = [line.strip() for line in (completed.stderr + "\n" + completed.stdout).splitlines() if line.strip()]
    if diagnostics:
        return "expected_failure", f"check exit {completed.returncode}: {diagnostics[0]}"
    return "expected_failure", f"check exit {completed.returncode}: verification failed"


def refresh_expectations(inventory: dict, samples_root: Path, check_bin: Path, jobs: int, timeout_seconds: int) -> None:
    tasks: list[tuple[str, str, str]] = []
    for project, pdata in inventory["projects"].items():
        for object_name, odata in pdata["objects"].items():
            for section in odata["sections"].keys():
                tasks.append((project, object_name, section))

    def classify(task: tuple[str, str, str]) -> tuple[str, str, str, str, str]:
        project, object_name, section = task
        odata = inventory["projects"][project]["objects"][object_name]
        inventory_classification = classify_from_inventory(odata["sections"][section])
        if inventory_classification is not None:
            status, reason = inventory_classification
            return project, object_name, section, status, reason
        object_path = samples_root / project / object_name
        status, reason = run_check(check_bin, object_path, section, timeout_seconds)
        return project, object_name, section, status, reason

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        for project, object_name, section, status, reason in executor.map(classify, tasks):
            odata = inventory["projects"][project]["objects"][object_name]
            overrides = odata.setdefault("test_overrides", {}).setdefault("sections", {})
            current = overrides.get(section)

            if status == "pass":
                overrides.pop(section, None)
            else:
                if current is not None and current.get("status") == status and current.get("reason"):
                    reason_to_store = current["reason"]
                else:
                    reason_to_store = reason
                overrides[section] = {"status": status, "reason": reason_to_store}

            if not overrides:
                odata.pop("test_overrides", None)


def main() -> int:
    args = parse_args()
    inventory_path = Path(args.inventory)
    samples_root = Path(args.samples_root)
    check_bin = Path(args.check_bin)

    if args.jobs < 1:
        print("error: --jobs must be >= 1", file=sys.stderr)
        return 2
    if args.timeout_seconds < 1:
        print("error: --timeout-seconds must be >= 1", file=sys.stderr)
        return 2
    if not inventory_path.exists():
        print(f"error: inventory not found: {inventory_path}", file=sys.stderr)
        return 2
    if not samples_root.exists():
        print(f"error: samples root not found: {samples_root}", file=sys.stderr)
        return 2
    if not check_bin.exists():
        print(f"error: check binary not found: {check_bin}", file=sys.stderr)
        return 2

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    refresh_expectations(inventory, samples_root, check_bin, args.jobs, args.timeout_seconds)
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {inventory_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
