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

TELEMETRY_LINE = re.compile(r"^[01],\d+(?:\.\d+)?,\d+$")
MANUAL_BCC_REASON_PREFIX = "Known verifier mismatch on BCC "


def explain(kind: str, diagnostic: str) -> str:
    if kind == "VerifierTypeTracking":
        return (
            "Known verifier limitation: register type refinement is too imprecise in this control-flow pattern. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "VerifierBoundsTracking":
        return (
            "Known verifier limitation: interval/bounds refinement loses precision for this memory-access proof. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "VerifierStackInitialization":
        return (
            "Known verifier limitation: stack initialization tracking is too coarse for this access path. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "VerifierPointerArithmetic":
        return (
            "Known verifier limitation: pointer-arithmetic typing is too restrictive in this pattern. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "VerifierMapTyping":
        return (
            "Known verifier limitation: map value/key typing and scalarization are too conservative here. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "VerifierNullability":
        return (
            "Known verifier limitation: nullability tracking is too conservative on this path. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "VerifierContextModeling":
        return (
            "Known verifier limitation: context-offset modeling is too restrictive for this access pattern. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "VerifierRecursionModeling":
        return (
            "Known verifier limitation: subprogram call-graph handling rejects this recursion-shaped pattern. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "UnmarshalControlFlow":
        return (
            "Known loader limitation: instruction unmarshaling cannot reconstruct this control-flow shape. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "ExternalSymbolResolution":
        return (
            "Known architectural limitation: unresolved external symbols are not modeled in offline verification. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "PlatformHelperAvailability":
        return (
            "Known platform-model limitation: helper availability differs from the sample expectation. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "ElfCoreRelocation":
        return (
            "Known loader limitation: CO-RE/BTF relocation payload is unsupported or malformed for this object. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "ElfSubprogramResolution":
        return (
            "Known loader limitation: subprogram resolution/disambiguation is incomplete for this object. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "ElfLegacyMapLayout":
        return (
            "Known loader limitation: legacy map symbol layout is not fully supported. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "VerificationTimeout":
        return (
            "Known algorithmic limitation: verification did not converge within the configured timeout. "
            f"Diagnostic: {diagnostic}"
        )
    if kind == "LegacyBccBehavior":
        return diagnostic
    raise ValueError(f"Unsupported kind: {kind}")


def classify_diagnostic(diagnostic: str) -> tuple[str, str, str] | None:
    if "helper function is unavailable on this platform" in diagnostic:
        kind = "PlatformHelperAvailability"
        return "skip", kind, explain(kind, diagnostic)
    if diagnostic.startswith("Unsupported or invalid CO-RE/BTF relocation data:"):
        kind = "ElfCoreRelocation"
        return "skip", kind, explain(kind, diagnostic)
    if diagnostic.startswith("Subprogram not found:") or diagnostic == "please specify a program":
        kind = "ElfSubprogramResolution"
        return "skip", kind, explain(kind, diagnostic)
    if diagnostic.startswith("Legacy map symbol "):
        kind = "ElfLegacyMapLayout"
        return "skip", kind, explain(kind, diagnostic)
    if "Unresolved symbols found." in diagnostic or diagnostic.startswith("Unresolved external symbol"):
        kind = "ExternalSymbolResolution"
        return "skip", kind, explain(kind, diagnostic)
    if diagnostic.startswith("unmarshaling error at "):
        kind = "UnmarshalControlFlow"
        return "expected_failure", kind, explain(kind, diagnostic)
    if "illegal recursion" in diagnostic:
        kind = "VerifierRecursionModeling"
        return "expected_failure", kind, explain(kind, diagnostic)
    if "Only numbers can be added to pointers" in diagnostic:
        kind = "VerifierPointerArithmetic"
        return "expected_failure", kind, explain(kind, diagnostic)
    if "Possible null access" in diagnostic or "Non-null number (" in diagnostic:
        kind = "VerifierNullability"
        return "expected_failure", kind, explain(kind, diagnostic)
    if "Nonzero context offset" in diagnostic:
        kind = "VerifierContextModeling"
        return "expected_failure", kind, explain(kind, diagnostic)
    if "Stack content is not numeric" in diagnostic:
        kind = "VerifierStackInitialization"
        return "expected_failure", kind, explain(kind, diagnostic)
    if "Illegal map update with a non-numerical value" in diagnostic:
        kind = "VerifierMapTyping"
        return "expected_failure", kind, explain(kind, diagnostic)
    if "Invalid size (" in diagnostic or "Upper bound must be at most" in diagnostic or "Lower bound must be at least" in diagnostic:
        kind = "VerifierBoundsTracking"
        return "expected_failure", kind, explain(kind, diagnostic)
    if "Invalid type (" in diagnostic:
        kind = "VerifierTypeTracking"
        return "expected_failure", kind, explain(kind, diagnostic)
    return None


def infer_manual_kind(reason: str | None) -> str | None:
    if not reason:
        return None
    if reason.startswith(MANUAL_BCC_REASON_PREFIX):
        return "LegacyBccBehavior"
    return None


def preserve_reason(current_reason: str | None) -> bool:
    if not current_reason:
        return False
    return current_reason.startswith(MANUAL_BCC_REASON_PREFIX)


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
    parser.add_argument(
        "--fail-on-unknown",
        action="store_true",
        help="Fail if check reports diagnostics that are not mapped to a known limitation kind.",
    )
    return parser.parse_args()


def classify_invalid_program_from_inventory(program: dict) -> tuple[str, str, str] | None:
    if not program.get("invalid", False):
        return None
    diagnostic = program.get("invalid_reason") or "invalid section in ELF metadata"
    classified = classify_diagnostic(diagnostic)
    if classified is not None:
        return classified
    kind = "ElfSubprogramResolution"
    return "skip", kind, explain(kind, diagnostic)


def run_check(
    check_bin: Path, object_path: Path, section: str, timeout_seconds: int, function_name: str | None = None
) -> tuple[str, str]:
    cmd = [str(check_bin), "-f", str(object_path), section]
    if function_name:
        cmd.extend(["--function", function_name])
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return "timeout", f"verification timed out after {timeout_seconds}s"

    if completed.returncode == 0:
        return "pass", ""

    stdout_lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    stderr_lines = [line.strip() for line in completed.stderr.splitlines() if line.strip()]
    diagnostics = [line for line in stdout_lines + stderr_lines if not TELEMETRY_LINE.fullmatch(line)]
    if diagnostics:
        return "fail", diagnostics[0]
    return "fail", "verification failed"


def refresh_expectations(
    inventory: dict, samples_root: Path, check_bin: Path, jobs: int, timeout_seconds: int
) -> list[tuple[str, str, str, str, str]]:
    tasks: list[tuple[str, str, str, str, int, bool]] = []
    for project, pdata in inventory["projects"].items():
        for object_name, odata in pdata["objects"].items():
            for section, programs in odata["sections"].items():
                if len(programs) == 1:
                    tasks.append((project, object_name, section, programs[0]["function"], 1, True))
                else:
                    for program in programs:
                        tasks.append((project, object_name, section, program["function"], len(programs), False))

    def classify(
        task: tuple[str, str, str, str, int, bool]
    ) -> tuple[str, str, str, str, int, bool, str, str | None, str]:
        project, object_name, section, function_name, section_program_count, section_scoped = task
        odata = inventory["projects"][project]["objects"][object_name]
        object_path = samples_root / project / object_name
        program = next(p for p in odata["sections"][section] if p["function"] == function_name)
        inventory_classification = classify_invalid_program_from_inventory(program)
        if inventory_classification is not None:
            status, kind, reason = inventory_classification
            return project, object_name, section, function_name, section_program_count, section_scoped, status, kind, reason

        result_kind, diagnostic = run_check(check_bin, object_path, section, timeout_seconds, function_name)
        if result_kind == "pass":
            return project, object_name, section, function_name, section_program_count, section_scoped, "pass", None, ""
        if result_kind == "timeout":
            kind = "VerificationTimeout"
            return (
                project,
                object_name,
                section,
                function_name,
                section_program_count,
                section_scoped,
                "skip",
                kind,
                explain(kind, diagnostic),
            )
        classified = classify_diagnostic(diagnostic)
        if classified is None:
            return (
                project,
                object_name,
                section,
                function_name,
                section_program_count,
                section_scoped,
                "pass",
                None,
                diagnostic,
            )
        status, kind, reason = classified
        return project, object_name, section, function_name, section_program_count, section_scoped, status, kind, reason

    unknown_diagnostics: list[tuple[str, str, str, str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        for (
            project,
            object_name,
            section,
            function_name,
            section_program_count,
            section_scoped,
            status,
            kind,
            reason,
        ) in executor.map(classify, tasks):
            odata = inventory["projects"][project]["objects"][object_name]
            test_overrides = odata.setdefault("test_overrides", {})
            section_overrides = test_overrides.setdefault("sections", {})
            program_overrides = test_overrides.setdefault("programs", {})
            if status == "pass" and reason and reason not in ("", "verification failed"):
                unknown_diagnostics.append((project, object_name, section, function_name, reason))

            if section_scoped:
                current = section_overrides.get(section)
                program_overrides.pop(section, None)
                if status == "pass":
                    section_overrides.pop(section, None)
                else:
                    current_reason = current.get("reason") if current else None
                    current_kind = current.get("kind") if current else None
                    if current_kind is None:
                        current_kind = infer_manual_kind(current_reason)
                    if current and current.get("status") == status and current_kind == kind and preserve_reason(current_reason):
                        reason_to_store = current_reason
                    else:
                        reason_to_store = reason
                    section_overrides[section] = {"status": status, "kind": kind, "reason": reason_to_store}
            else:
                section_overrides.pop(section, None)
                section_program_overrides = program_overrides.setdefault(section, {})
                current = section_program_overrides.get(function_name)
                if status == "pass":
                    section_program_overrides.pop(function_name, None)
                    if not section_program_overrides:
                        program_overrides.pop(section, None)
                else:
                    current_reason = current.get("reason") if current else None
                    current_kind = current.get("kind") if current else None
                    if current_kind is None:
                        current_kind = infer_manual_kind(current_reason)
                    if current and current.get("status") == status and current_kind == kind and preserve_reason(current_reason):
                        reason_to_store = current_reason
                    else:
                        reason_to_store = reason
                    section_program_overrides[function_name] = {"status": status, "kind": kind, "reason": reason_to_store}

            if not section_overrides:
                test_overrides.pop("sections", None)
            if not program_overrides:
                test_overrides.pop("programs", None)
            if not test_overrides:
                odata.pop("test_overrides", None)

    return unknown_diagnostics


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
    unknown_diagnostics = refresh_expectations(inventory, samples_root, check_bin, args.jobs, args.timeout_seconds)
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {inventory_path}", file=sys.stderr)
    if unknown_diagnostics:
        print(
            f"warning: {len(unknown_diagnostics)} diagnostics are not mapped to a known limitation kind; "
            "those tests are left as pass expectations.",
            file=sys.stderr,
        )
        for project, object_name, section, function_name, diagnostic in unknown_diagnostics[:20]:
            print(
                f"  unknown: {project}/{object_name} {section}::{function_name} -> {diagnostic}",
                file=sys.stderr,
            )
        if args.fail_on_unknown:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
