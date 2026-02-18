# Prevail Diagnostic Reporting System

## Feature Specification

| Field | Value |
|-------|-------|
| **Version** | 1.0 (Draft) |
| **Date** | 2026-02-18 |
| **Status** | Proposed |
| **Related Issues** | #995, #1010 |

---

## 1. Executive Summary

Prevail's current diagnostic output has two modes: minimal (error only) and verbose (full CFG dump). For large BPF programs (10k+ instructions), verbose mode produces overwhelming output while minimal mode lacks debugging context. This specification defines a **Diagnostic Reporting System** that provides targeted, actionable failure information.

---

## 2. Problem Statement

### 2.1 Current State

| Mode | Flag | Output | Usefulness |
|------|------|--------|------------|
| Minimal | (default) | ~5 lines | Error location only, no context |
| Verbose | `-v` | Variable (stops at error) | **Broken**: stops at first error, hiding loop predecessors |

**Note:** Current `-v` behavior is buggy (#1010) - it stops printing at first error, so blocks appearing later in instruction order (including loop back-edges) are never shown.

### 2.2 Specific Problems

**P1: Verbose mode stops at first error (#1010)**
- Loop predecessor invariants are hidden
- Labels referenced in output (e.g., `from 339:`) never appear
- Cannot debug loop-related failures

**P2: No intermediate verbosity (#995)**
- Either too little or too much information
- No way to see just the relevant slice
- Large programs produce unusable output

**P3: No structured output**
- Text-only output
- No machine-readable format for tooling
- IDE integration requires parsing fragile text

---

## 3. Stakeholders

| Stakeholder | Role | Primary Needs |
|-------------|------|---------------|
| **BPF Developer** | Writes BPF programs | Understand why program rejected; fix quickly |
| **Verifier Developer** | Maintains Prevail | Debug abstract interpretation; trace state flow |
| **Platform Team** | Integrates Prevail | CI/CD integration; automated error reporting |
| **IDE/Tool Author** | Builds developer tools | Structured output; stable API |

---

## 4. Use Cases

### UC-1: Debug Simple Verification Failure

**Actor:** BPF Developer
**Precondition:** Program fails verification with bounds check error
**Flow:**
1. Developer runs `check program.o`
2. Sees error: "Upper bound must be at most r0.shared_region_size"
3. Runs `check program.o --slice` to see failure context
4. Output shows 15-instruction trace leading to error
5. Developer identifies missing bounds check, fixes code

**Acceptance Criteria:**
- [ ] Slice output ≤ 50 instructions for typical failures
- [ ] Trace shows data dependencies clearly
- [ ] Register types/values shown at each step

### UC-2: Debug Loop-Related Failure

**Actor:** BPF Developer
**Precondition:** Program fails at instruction inside loop; error involves loop-carried state
**Flow:**
1. Developer runs `check program.o -v`
2. Output includes ALL invariants (full CFG), including instruction 339 which has a backward edge to 184
3. Error at instruction 184 is shown inline with its context
4. Developer sees how loop widening at instruction 339 affected bounds flowing into 184
5. Developer identifies that widening lost precision, adds loop bound annotation

**Alternative Flow (large program):**
1. Developer runs `check program.o --reachable` to reduce output size
2. Output includes only blocks from which error location is reachable
3. Irrelevant code paths are excluded, making output manageable

**Acceptance Criteria:**
- [ ] `-v` shows ALL blocks including those after error in instruction order
- [ ] Loop back-edge predecessors are always visible
- [ ] `--reachable` filters to subset of `-v` (blocks reaching error only)

### UC-3: CI Integration

**Actor:** Platform Team
**Precondition:** BPF programs verified in CI pipeline
**Flow:**
1. CI runs `check program.o --format=sarif`
2. Output is SARIF JSON with error location, message, code
3. CI system uploads to code scanning dashboard
4. Developer sees inline error in PR diff view

**Acceptance Criteria:**
- [ ] SARIF output validates against SARIF 2.1 schema
- [ ] Error locations map to source lines (when debug info present)
- [ ] Stable error codes for categorization

### UC-4: Interactive Debugging Session

**Actor:** Verifier Developer
**Precondition:** Complex failure requires step-by-step investigation
**Flow:**
1. Developer runs `check program.o --interactive`
2. REPL prompt appears with program loaded
3. Developer queries: `show invariant at 184`
4. Developer queries: `show predecessors of 184`
5. Developer queries: `show history of r3`
6. Developer identifies widening lost precision at iteration 5

**Acceptance Criteria:**
- [ ] Sub-second response for queries
- [ ] State preserved across queries (no re-analysis)
- [ ] Can export session transcript

### UC-5: IDE Hover Information

**Actor:** IDE/Tool Author
**Precondition:** VS Code extension wants to show verification info
**Flow:**
1. Extension starts Prevail in server mode
2. User hovers over BPF instruction in editor
3. Extension queries: `GET /invariant?file=prog.o&line=42`
4. Prevail returns JSON with register types/values at that point
5. Extension shows hover tooltip with verification state

**Acceptance Criteria:**
- [ ] Server responds to queries without re-analyzing
- [ ] Incremental re-analysis on file change
- [ ] < 100ms response time for cached queries

---

## 5. Requirements

### 5.1 Functional Requirements

#### FR-1: Verbosity Modes

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-1.1 | System SHALL support `--quiet` mode (exit code only) | P2 |
| FR-1.2 | System SHALL support default mode (error + location) | P1 |
| FR-1.3 | System SHALL support `--slice` mode (backward slice to error) | P1 |
| FR-1.4 | System SHALL support `--reachable` mode (blocks from which error is reachable) | P1 |
| FR-1.5 | System SHALL fix `-v/--verbose` to show ALL blocks (not stop at error) | P1 |

**Verbosity Hierarchy:**
```
--quiet  ⊂  (default)  ⊂  --slice  ⊂  --reachable  ⊂  -v
   │           │            │             │            │
exit code   error msg    ~20 insns    ~100s insns   ALL insns
```

- `-v` (verbose): Full CFG, all invariants, all blocks — **must not stop at first error**
- `--reachable`: Subset of `-v` — only blocks from which error location is CFG-reachable
- `--slice`: Subset of `--reachable` — only instructions with data/control dependency to error

#### FR-2: Output Filtering

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-2.1 | Slice mode SHALL include only instructions with data dependency to error | P1 |
| FR-2.2 | Slice mode SHALL track dependencies through registers R0-R10 | P1 |
| FR-2.3 | Slice mode SHALL track dependencies through stack memory | P2 |
| FR-2.4 | Reachable mode SHALL compute forward CFG reachability to error | P1 |
| FR-2.5 | System SHOULD support filtering by register (`--filter=r3`) | P3 |
| FR-2.6 | System SHOULD support filtering by label range (`--range=100:200`) | P3 |

#### FR-3: Output Formats

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-3.1 | System SHALL support `--format=text` (human-readable, default) | P1 |
| FR-3.2 | System SHALL support `--format=json` (machine-readable) | P1 |
| FR-3.3 | System SHOULD support `--format=sarif` (IDE integration) | P2 |
| FR-3.4 | System SHOULD support `--format=dot` (CFG visualization) | P3 |

#### FR-4: Error Handling

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.1 | System SHALL continue analysis after first error when `--all-errors` specified | P2 |
| FR-4.2 | System SHALL report up to N errors (configurable, default 10) | P2 |
| FR-4.3 | Each error SHALL include: location, error code, message, instruction | P1 |
| FR-4.4 | Each error SHOULD include: pre-state, failing assertion, suggested fix | P2 |

#### FR-5: Interactive Mode

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-5.1 | System SHOULD support `--interactive` REPL mode | P3 |
| FR-5.2 | System SHOULD support `--server` mode for external queries | P3 |
| FR-5.3 | Server mode SHOULD cache analysis results | P3 |
| FR-5.4 | Server mode SHOULD support incremental re-analysis | P4 |

### 5.2 Non-Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| NFR-1 | Slice computation SHALL complete in O(slice_size), not O(program_size) | P1 |
| NFR-2 | Output SHALL be deterministic (same input → same output) | P1 |
| NFR-3 | JSON schema SHALL be versioned and backward-compatible | P2 |
| NFR-4 | Existing `-v` behavior SHALL be preserved for compatibility | P1 |
| NFR-5 | Memory usage SHALL not exceed 2x current for new modes | P2 |
| NFR-6 | New flags SHALL not affect verification correctness | P1 |

---

## 6. Data Model

### 6.1 Verification Result

```typescript
interface VerificationResult {
  version: string;                    // Schema version
  program: ProgramInfo;
  outcome: "pass" | "fail" | "error";
  errors: Error[];
  statistics: Statistics;
  invariants?: Map<Label, Invariant>; // Only if requested
}

interface ProgramInfo {
  filename: string;
  section: string;
  instruction_count: number;
  maps: MapInfo[];
}

interface Error {
  code: ErrorCode;                    // e.g., "E001_BOUNDS_CHECK"
  severity: "error" | "warning";
  location: Location;
  message: string;
  instruction: string;
  pre_state?: AbstractState;          // If verbose
  assertion?: string;                 // What was checked
  suggestion?: string;                // How to fix
}

interface Location {
  label: string;                      // CFG label
  pc: number;                         // Instruction index
  source?: SourceLocation;            // If debug info present
}

interface SourceLocation {
  file: string;
  line: number;
  column?: number;
}
```

### 6.2 Slice

```typescript
interface Slice {
  error: Error;
  trace: SliceEntry[];                // Ordered: error → root cause
  projected_state: ProjectedState;
}

interface SliceEntry {
  label: string;
  pc: number;
  instruction: string;
  relevance: "direct" | "control" | "data";
  variables_affected: string[];
  invariant?: Invariant;
}

interface ProjectedState {
  registers: Map<Register, TypedValue>;
  stack_regions: StackRegion[];
}
```

### 6.3 Error Codes

| Code | Name | Description |
|------|------|-------------|
| E001 | BOUNDS_UPPER | Access exceeds upper bound |
| E002 | BOUNDS_LOWER | Access below lower bound (negative offset) |
| E003 | TYPE_MISMATCH | Operation on incompatible types |
| E004 | UNINITIALIZED | Read of uninitialized register/memory |
| E005 | INVALID_HELPER | Invalid helper function call |
| E006 | STACK_OVERFLOW | Stack access out of range |
| E007 | DIVISION_ZERO | Possible division by zero |
| E008 | INVALID_MAP | Invalid map operation |
| E009 | LOOP_BOUND | Cannot prove loop termination |
| E010 | UNREACHABLE | Unreachable code detected |

---

## 7. User Interface

### 7.1 Command Line

```
USAGE:
    check [OPTIONS] <program.o> [section]

VERBOSITY OPTIONS (mutually exclusive, most verbose wins):
    -v, --verbose          Full output: ALL invariants, ALL blocks (fixes #1010)
    --reachable            Filtered: only blocks from which error is reachable
    --slice                Minimal: backward slice showing data/control deps to error
    -q, --quiet            Silent: exit code only

ERROR HANDLING:
    --all-errors           Report multiple errors (default: stop at first)
    --max-errors <N>       Maximum errors to report (default: 10)

OUTPUT FORMAT:
    --format <FORMAT>      Output format: text (default), json, sarif, dot

FILTERING:
    --filter <EXPR>        Filter output (e.g., "r3", "stack", "100:200")

INTERACTIVE:
    --interactive          Start REPL mode
    --server [PORT]        Start server mode
```

**Verbosity comparison:**

| Flag | Blocks shown | Use case |
|------|--------------|----------|
| (default) | Error only | Quick check |
| `--slice` | ~10-50 instructions | Understand single failure |
| `--reachable` | ~100s instructions | Debug complex control flow |
| `-v` | ALL (thousands) | Full audit, verifier debugging |

### 7.2 Example Outputs

**Default (error only):**
```
program.o:184: error[E001]: Upper bound must be at most r0.shared_region_size
  --> r1 = *(u64 *)(r0 + 80)
```

**Slice mode:**
```
program.o:184: error[E001]: Upper bound must be at most r0.shared_region_size

Failure trace (most recent last):
  170: r0 = *(u64 *)(r1 + 0)     ; r0: ptr(shared, offset=[0,∞))
  175: r2 = 80                   ; r2: num(80)
  180: if r2 > r3 goto 190       ; r3: num([0,64])  ← bounds not checked
  184: r1 = *(u64 *)(r0 + 80)    ; ERROR: offset 80 exceeds max 64

State at error:
  r0: ptr(shared, offset=[0,∞), size=[0,64])
  r3: num([0,64])
```

**JSON format:**
```json
{
  "version": "1.0",
  "outcome": "fail",
  "errors": [{
    "code": "E001",
    "location": {"label": "184", "pc": 184},
    "message": "Upper bound must be at most r0.shared_region_size",
    "instruction": "r1 = *(u64 *)(r0 + 80)"
  }]
}
```

---

## 8. Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        Prevail CLI                             │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Argument Parser                        │  │
│  │  --slice, --reachable, --format, --filter, etc.          │  │
│  └─────────────────────────┬────────────────────────────────┘  │
└────────────────────────────┼───────────────────────────────────┘
                             │
┌────────────────────────────▼───────────────────────────────────┐
│                      Analysis Engine                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Loader    │→ │   Fixpoint  │→ │   VerificationResult    │ │
│  │   Parser    │  │   Iterator  │  │   (invariants, errors)  │ │
│  └─────────────┘  └─────────────┘  └────────────┬────────────┘ │
└─────────────────────────────────────────────────┼──────────────┘
                                                  │
┌─────────────────────────────────────────────────▼──────────────┐
│                    Diagnostic Engine                           │
│                                                                │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │  Slice Computer │  │ Reachability     │  │ State         │  │
│  │                 │  │ Analyzer         │  │ Projector     │  │
│  │ - Data deps     │  │ - Forward reach  │  │ - Filter vars │  │
│  │ - Control deps  │  │ - Backward reach │  │ - Summarize   │  │
│  └────────┬────────┘  └────────┬─────────┘  └───────┬───────┘  │
│           │                    │                    │          │
│  ┌────────▼────────────────────▼────────────────────▼───────┐  │
│  │                    Query Executor                        │  │
│  │  - Filter by mode (slice, reachable, full)               │  │
│  │  - Apply user filters (--filter)                         │  │
│  │  - Collect results                                       │  │
│  └─────────────────────────────┬────────────────────────────┘  │
│                                │                               │
│  ┌─────────────────────────────▼────────────────────────────┐  │
│  │                   Output Formatters                      │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │  │
│  │  │   Text   │  │   JSON   │  │  SARIF   │  │   DOT    │  │  │
│  │  │ Formatter│  │ Formatter│  │ Formatter│  │ Formatter│  │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

---

## 9. Open Questions

| # | Question | Options | Recommendation |
|---|----------|---------|----------------|
| 1 | When to compute slice? | During analysis / Post-hoc | Post-hoc (cleaner separation) |
| 2 | Multiple errors behavior? | Stop at first / Collect all / Configurable | Configurable (default: first) |
| 3 | Backward slice algorithm? | Syntactic / Semantic / Hybrid | Semantic (track abstract values) |
| 4 | Server protocol? | HTTP REST / gRPC / Custom IPC | HTTP REST (simplicity) |
| 5 | SARIF version? | 2.0 / 2.1 | 2.1 (latest stable) |

---

## 10. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Slice size reduction | 95% smaller than full output | Compare `--slice` vs `-v` line counts |
| Debug time reduction | 50% faster issue resolution | User study / feedback |
| Tooling adoption | 3+ external tools use JSON output | Track integrations |
| Error clarity | 80% of users understand error on first read | Survey |

---

## Appendix A: Related Work

- **Infer**: Facebook's static analyzer has `--debug` and `--print-logs` modes
- **CBMC**: Provides counterexample traces and minimal witnesses
- **Frama-C**: GUI with interactive exploration of abstract state
- **SARIF**: Static Analysis Results Interchange Format (OASIS standard)

## Appendix B: References

- Issue #995: Add Intermediate Verbosity Mode for Minimal Failure Slices
- Issue #1010: Invariant output stops at first error
- SARIF Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
