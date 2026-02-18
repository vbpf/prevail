# Diagnostic Reporting System - Implementation Roadmap

| Field | Value |
|-------|-------|
| **Related Spec** | [diagnostic-reporting-spec.md](diagnostic-reporting-spec.md) |
| **Date** | 2026-02-18 |
| **Status** | Draft |

---

## Overview

This document outlines a phased implementation approach for the Diagnostic Reporting System specified in [diagnostic-reporting-spec.md](diagnostic-reporting-spec.md). Phases are ordered by value delivered and implementation complexity.

---

## Phase 1: Core Diagnostic Modes (MVP)

**Goal:** Fix immediate pain points from issues #995 and #1010.

### Scope

| Requirement | Description |
|-------------|-------------|
| FR-1.5 | Fix `-v` to show ALL blocks (don't stop at error) |
| FR-1.3 | Add `--slice` mode with basic backward trace |
| FR-1.4 | Add `--reachable` mode (CFG filter to error) |
| FR-3.1 | Text output formatting for new modes |

### Deliverables

1. **Fix `-v` bug** (`src/printing.cpp`)
   - Remove early `return` on error in `print_invariants`
   - Ensure all blocks printed regardless of error state

2. **Add `--reachable` flag**
   - Compute forward CFG reachability from each block to error location
   - Filter output to only reachable blocks
   - Reuse existing CFG traversal infrastructure

3. **Add `--slice` flag**
   - Implement syntactic backward slice from error
   - Track register dependencies (R0-R10)
   - Output filtered instruction trace with invariants

4. **CLI integration**
   - Add new flags to argument parser
   - Ensure mutual exclusivity / precedence rules

### Acceptance Tests

- [ ] `check -v` on loop failure shows ALL blocks including those after error PC
- [ ] `check --reachable` shows only blocks that can reach error
- [ ] `check --slice` produces ≤ 50 instructions for typical failures
- [ ] Existing test suite passes unchanged

### Estimated Effort

2-4 weeks

---

## Phase 2: Structured Output

**Goal:** Enable tooling integration with machine-readable output.

### Scope

| Requirement | Description |
|-------------|-------------|
| FR-3.2 | Add `--format=json` output |
| FR-3.3 | Add `--format=sarif` output |
| FR-4.1 | Add `--all-errors` flag |
| FR-4.2 | Add `--max-errors` flag |
| NFR-3 | Versioned JSON schema |

### Deliverables

1. **JSON output format**
   - Implement `VerificationResult` serialization
   - Version the schema (start at 1.0)
   - Document schema in `docs/json-schema.md`

2. **SARIF output format**
   - Map Prevail errors to SARIF result objects
   - Include source locations when DWARF available
   - Validate against SARIF 2.1 schema

3. **Multi-error support**
   - Continue analysis after first error when `--all-errors`
   - Limit output with `--max-errors`
   - Deduplicate related errors

### Acceptance Tests

- [ ] JSON output validates against published schema
- [ ] SARIF output works with VS Code SARIF Viewer extension
- [ ] `--all-errors` reports multiple independent failures
- [ ] `--max-errors=5` stops after 5 errors

### Estimated Effort

2-3 weeks

---

## Phase 3: Advanced Filtering

**Goal:** Fine-grained control over diagnostic output.

### Scope

| Requirement | Description |
|-------------|-------------|
| FR-2.3 | Track slice dependencies through stack memory |
| FR-2.5 | Add `--filter=r3` register filtering |
| FR-2.6 | Add `--range=100:200` label filtering |
| FR-3.4 | Add `--format=dot` CFG visualization |

### Deliverables

1. **Enhanced backward slice**
   - Track dependencies through stack slots
   - Consider control dependencies (branch conditions)

2. **Register filter**
   - `--filter=r3` shows only instructions affecting R3
   - Useful for "how did R3 get this value?" questions

3. **Label range filter**
   - `--range=100:200` limits output to label range
   - Useful for focusing on specific code regions

4. **DOT output**
   - Generate GraphViz DOT format for CFG
   - Include invariants as node labels
   - Highlight error path

### Acceptance Tests

- [ ] `--filter=r3` shows only R3-relevant instructions
- [ ] `--range=100:200` limits output to specified range
- [ ] DOT output renders correctly in GraphViz
- [ ] Stack-tracking slice catches stack-mediated dependencies

### Estimated Effort

4-6 weeks

---

## Phase 4: Interactive Mode

**Goal:** Enable exploratory debugging for complex failures.

### Scope

| Requirement | Description |
|-------------|-------------|
| FR-5.1 | Add `--interactive` REPL mode |
| FR-5.2 | Add `--server` mode |
| FR-5.3 | Server result caching |
| FR-5.4 | Incremental re-analysis |

### Deliverables

1. **REPL interface**
   - Commands: `show invariant at <label>`, `show slice to <label>`, etc.
   - Tab completion for labels, registers
   - Session history and transcript export

2. **Server mode**
   - HTTP REST API for queries
   - Endpoints: `/analyze`, `/invariant`, `/slice`
   - WebSocket for incremental updates

3. **Caching and incremental analysis**
   - Cache analysis results per-program
   - Invalidate on file change
   - Incremental re-analysis for small changes

### Acceptance Tests

- [ ] REPL responds to `show invariant at <label>` in < 1s
- [ ] Server responds to `/invariant` queries without re-analyzing
- [ ] File change triggers incremental update
- [ ] Server handles concurrent clients

### Estimated Effort

8-16 weeks (significant architectural changes)

---

## Dependencies

```
Phase 1 ─────► Phase 2 ─────► Phase 3
                              │
                              ▼
                           Phase 4
```

- Phase 2 depends on Phase 1 (output infrastructure)
- Phase 3 depends on Phase 2 (filtering builds on structured output)
- Phase 4 depends on Phase 3 (interactive mode uses all filtering capabilities)

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Semantic slicing complexity | Phase 1 delay | Start with syntactic slice; enhance later |
| SARIF schema complexity | Phase 2 delay | Implement minimal SARIF first; add fields incrementally |
| Server architecture changes | Phase 4 delay | Keep as optional; core CLI remains batch-mode |
| Performance regression | User impact | Benchmark before/after; optimize hot paths |

---

## Success Criteria

| Phase | Success Metric |
|-------|----------------|
| Phase 1 | Issues #995 and #1010 closed; users can debug loop failures |
| Phase 2 | ≥1 external tool integrates JSON output |
| Phase 3 | Power users report improved debugging workflow |
| Phase 4 | IDE extension prototype demonstrated |
