#!/usr/bin/env python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

import argparse
import json
from collections import defaultdict
from pathlib import Path

FIXABLE_KINDS = set()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit non-pass verify expectations from elf_inventory.json.")
    parser.add_argument("--inventory", default="test-data/elf_inventory.json", help="Inventory JSON path.")
    parser.add_argument("--output", default="test-data/verify_reason_audit.json", help="Audit JSON output path.")
    parser.add_argument("--max-samples", type=int, default=10, help="Maximum samples per unique reason entry.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    inventory_path = Path(args.inventory)
    if not inventory_path.exists():
        raise SystemExit(f"error: inventory not found: {inventory_path}")

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))

    entries: dict[tuple[str, str, str], dict] = {}
    counts_by_kind = defaultdict(int)
    counts_by_status = defaultdict(int)

    def add(status: str, kind: str, reason: str, project: str, object_name: str, section: str, function: str | None):
        key = (status, kind, reason)
        if key not in entries:
            entries[key] = {
                "status": status,
                "kind": kind,
                "fixable": kind in FIXABLE_KINDS,
                "reason": reason,
                "count": 0,
                "samples": [],
            }
        rec = entries[key]
        rec["count"] += 1
        if len(rec["samples"]) < args.max_samples:
            sample = {"project": project, "object": object_name, "section": section}
            if function is not None:
                sample["function"] = function
            rec["samples"].append(sample)
        counts_by_kind[kind] += 1
        counts_by_status[status] += 1

    for project, pdata in inventory["projects"].items():
        for object_name, odata in pdata["objects"].items():
            overrides = odata.get("test_overrides", {})
            for section, override in overrides.get("sections", {}).items():
                status = override.get("status")
                if status not in ("expected_failure", "skip"):
                    continue
                add(status, override["kind"], override["reason"], project, object_name, section, None)
            for section, program_map in overrides.get("programs", {}).items():
                for function, override in program_map.items():
                    status = override.get("status")
                    if status not in ("expected_failure", "skip"):
                        continue
                    add(status, override["kind"], override["reason"], project, object_name, section, function)

    audit = {
        "fixable_kinds": sorted(FIXABLE_KINDS),
        "summary": {
            "nonpass_total": sum(counts_by_status.values()),
            "by_status": dict(sorted(counts_by_status.items())),
            "by_kind": dict(sorted(counts_by_kind.items())),
            "unique_reasons": len(entries),
        },
        "entries": sorted(
            entries.values(),
            key=lambda e: (e["fixable"], e["kind"], e["status"], -e["count"], e["reason"]),
        ),
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
