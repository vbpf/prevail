# Prevail repository guide for AI agents

## Soundness-first analysis principles
- **Soundness beats throughput.** When updating the analyser or verifier, favour transfer functions and abstractions with explicit, auditable invariants over heuristic shortcuts. If a micro-optimisation risks dropping constraints that protect against false negatives, keep the precise version and document why it is safe.
- **Prove invariants when possible.** Encode the assumptions an analysis relies on—preconditions, lattice properties, monotonicity—directly in code comments, assertions, or type-level checks before trusting experiments. When you need executable evidence, add deterministic tests or YAML fixtures that demonstrate both the sound and the unsound outcomes you are ruling out.
- **Narrate the reasoning.** Any change that affects analysis results should spell out the argument for soundness: what inputs are assumed, what invariants are maintained, and how the change preserves them. Prefer control flow that makes this reasoning self-evident to future auditors.
- **Default to conservative behaviour.** Introduce new analysis features behind flags or with stricter defaults until you can show they do not compromise soundness; never silently relax checks or widen abstractions without justification.
- **Optimise for auditability.** Choose designs that are easy to step through and review by hand—even if they are marginally slower or more verbose—so that a future engineer can re-establish the soundness argument quickly.

## Quick project facts
- **Language & standards:** Core verifier is implemented in modern C++20 (see `CMakeLists.txt`).
- **Primary deliverables:**
  - `check`: command-line verifier for eBPF object files.
  - `tests`: Catch2-based regression suite.
  - `run_yaml`: YAML test case runner.
- **Third-party code:** resides under `external/` and is treated as vendored dependencies. Do not edit these unless explicitly asked.

## Repository map
- `src/`
  - `asm_*`, `cfg/`, `arith/`, `crab/`, `linux/`: verifier implementation broken down by domain.
  - `main/`: entry points for command-line tools: `check`.
  - `test/`: Catch2 unit and integration tests.
- `ebpf-samples/`: sample ELF objects used for manual experimentation.
- `scripts/`: developer utilities (formatting, license checks, git hooks).
- `test-data/` and `test-schema.yaml`: YAML-driven verification fixtures.

## Build & test workflow
1. **Configure** (tests are enabled automatically when working from a git checkout):
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   ```
2. **Build everything** (produces binaries in the repo root via `RUNTIME_OUTPUT_DIRECTORY`):
   ```bash
   cmake --build build
   ```
3. **Run tests** using the generated `tests` executable:
   ```bash
   ./tests                      # from the repo root
   ```
4. **Spot-check the verifier** against bundled samples:
   ```bash
   ./check ebpf-samples/cilium/bpf_lxc.o 2/1
   ```
5. **Capture reasoning.** When a change introduces or relies on a new invariant, add a targeted regression test and document the invariant in code comments or `docs/` notes so future auditors can reconstruct the argument.

### Platform notes
- Linux & macOS: require `cmake`, `clang++`/`g++` with C++20 support, Boost, yaml-cpp, and Microsoft GSL (fetched automatically).
- Windows: use Visual Studio Build Tools 2022; NuGet will fetch Boost, and yaml-cpp is built via `ExternalProject_Add`.
- Docker: `docker build -t verifier .` then run the resulting image for a hermetic environment. Use `--privileged` to exercise the Linux kernel verifier.

## Coding standards & automation
- **Formatting:** Run `./scripts/format-code --staged` before committing (mirrors the Git hook). It wraps `clang-format` and warns if the version differs from the project baseline.
- **License headers:** Ensure new C/C++ sources include the standard SPDX header; validate with `./scripts/check-license.sh <files>`.
- **Git hooks:** `scripts/pre-commit` installs automatically from CMake to enforce names, whitespace, formatting, and license headers.
- **Static includes:** Headers prefer `#pragma once`; follow existing patterns within each subdirectory.
- **Review for soundness.** Before finishing a change, walk through the modified control-flow and data-flow manually to ensure no undefined behaviour or unchecked user input paths were introduced.

## Working efficiently
- Prefer adding new verifier logic under the matching subsystem directory (`cfg/`, `crab/`, etc.) to keep separation of concerns.
- Tests live beside the production code in `src/test`; add focused Catch2 cases when modifying verifier behaviour.
- When touching YAML-driven fixtures, update schemas in `test-schema.yaml` if new fields are introduced and exercise them via `run_yaml`.
- Avoid editing vendored sources beneath `external/` unless the task explicitly targets them; instead, wrap behaviour in our own code where possible.
- Keep runtime/tooling flags documented by updating `README.md` if you introduce new CLI options.
- When in doubt, favour explicit error handling and early exits to surface problems instead of deferring to implicit behaviour.
