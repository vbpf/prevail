#!/usr/bin/env python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

import pathlib, re, sys

# Match ANY macro that starts with TEST_CONFORMANCE and capture the first string literal
# that ends with .data (handles future variants, extra args, whitespace, and newlines).
MACRO_RE = re.compile(
    r'TEST_CONFORMANCE[A-Za-z0-9_]*\s*\(\s*([\'"])([^\'"]+?\.data)\1',
    re.DOTALL
)

DATA_DIR = pathlib.Path("external/bpf_conformance/tests")
CONFORMANCE_TEST_FILE = pathlib.Path("src/test/test_conformance.cpp")

txt = pathlib.Path(CONFORMANCE_TEST_FILE).read_text(encoding="utf-8", errors="ignore")
listed = {m.group(2) for m in MACRO_RE.finditer(txt)}
on_disk = {p.name for p in pathlib.Path(DATA_DIR).glob("*.data") if p.is_file()}

missing = sorted(on_disk - listed)
if missing:
    print("Missing (present but not tested):")
    for n in missing:
        print(f'TEST_CONFORMANCE("{n}")')
    sys.exit(1)
