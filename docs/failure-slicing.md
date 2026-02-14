# Failure Slicing

Failure slicing is a diagnostic feature that computes the minimal subset of a program
that contributed to a verification failure. When verification fails, instead of showing
the entire CFG with all invariants, failure slicing identifies only the instructions and
state that are causally relevant to the error.

## Motivation

Large eBPF programs can have thousands of instructions, but a verification failure
typically involves only a small fraction of them. Failure slicing helps developers and
LLM-based tools focus on the relevant code path without being overwhelmed by unrelated
instructions.

## Quick Start

```bash
./bin/check program.o section --failure-slice
```

Output includes:
- Error message and location
- Relevant registers at the failure point
- Slice size (number of causal instructions)
- Control-flow summary (branch-path skeleton through the slice)
- Filtered CFG showing only relevant invariants and instructions
- Per-predecessor invariants at join points (when applicable)

## Concepts

### Backward Slicing

Given a failure at label L involving registers R1, R2, …, the algorithm walks backward
through the CFG to find all instructions that contributed to the values in those
registers at that point. The walk tracks both **data dependencies** (which registers
flow into which) and **control dependencies** (which branch conditions determine
reachability of the failing instruction).

For example, if verification fails because "R1 is not a valid pointer":

1. The slice starts with R1 as relevant
2. If R1 was defined by `r1 = r2 + 4`, then R2 becomes relevant
3. If R2 was loaded from the stack `r2 = *(r10 - 8)`, then stack offset -8 becomes relevant
4. If the failing label is guarded by `assume r4 == 0`, then R4 becomes relevant
5. The algorithm continues until it reaches program entry or exhausts relevance

### Two-Map Architecture: Visited vs Slice Labels

The backward walk maintains two separate maps:

- **`visited`**: Tracks *all* labels explored during traversal, used for deduplication.
  A label that is merely traversed (e.g., a passthrough where r3 flows through unchanged)
  appears in `visited` but not in the output.
- **`slice_labels`**: Tracks only labels whose instructions actually *interact* with
  relevant registers (read or write them). Only these labels appear in the output.

This separation prevents "pass-through explosion" where the entire program would be
included just because a register flows through many blocks without being read or written.

### Per-Label Relevance

Each label in the slice tracks which registers and stack offsets are relevant at that
point. This enables filtered display of invariants — showing only the parts of the
abstract state that matter for understanding the failure.

### Instruction Dependencies

During forward analysis, the verifier optionally records what each instruction reads
and writes:

- **Registers read/written**: e.g., `r1 = r2 + r3` reads R2, R3 and writes R1
- **Registers clobbered**: e.g., a helper call clobbers R0–R5 without reading them
- **Stack offsets read/written**: e.g., `*(r10 - 8) = r1` writes stack[-8]

This information is computed once during verification and reused for slicing.

## CLI Usage

```bash
# Basic usage — shows first failure with filtered output
./bin/check program.o section --failure-slice

# Control backward traversal depth (default: 200 worklist steps)
./bin/check program.o section --failure-slice --failure-slice-depth 500

# With simplified basic blocks (collapses sequential instructions)
./bin/check program.o section --failure-slice --simplify

# Combined with other options
./bin/check program.o section --failure-slice --line-info
```

**Default behavior:**
- Shows only the first failure (not all failures)
- Disables simplification (shows each instruction separately)
- Filters assertions to only show those involving relevant registers
- Filters invariants to only show constraints involving relevant registers

## Output Format

```text
=== Failure Slice 1 of 1 ===

[ERROR] Upper bound must be at most packet_size (valid_access(r3.offset+32, width=8) for write)
[LOCATION] 230
[RELEVANT REGISTERS] r3, r4
[SLICE SIZE] 14 program points

[CONTROL FLOW] 209, 210, ..., {225:226 | 225:228 (assume r1 > r2)} -> 229 (if r4 != 0), 229:230 (assume r4 == 0), 230 FAIL

[CAUSAL TRACE]
Pre-invariant : [
    r3.type=packet, r4.type=number,
    packet_size=34,
    r3.packet_offset=[22, 82], r4.svalue=[-22, 0],
    ...]
  from 209;
209:
  r3 = r1;
  ...
```

### Output Sections

| Section | Description |
|---------|-------------|
| `[ERROR]` | The verification error message and assertion |
| `[LOCATION]` | The failing label (PC or edge label) |
| `[RELEVANT REGISTERS]` | Registers/stack offsets at the failure point that the error depends on |
| `[SLICE SIZE]` | Number of program points in the slice |
| `[CONTROL FLOW]` | Compact branch-path skeleton: labels in order, with Assume/Jmp annotations |
| `[CAUSAL TRACE]` | Filtered CFG with per-instruction invariants for slice labels only |

## Algorithm Details

### Step 1: Seed from Assertion

Extract registers directly from the failed assertion type:
- `ValidAccess{.reg = R1}` → seed = {R1}
- `TypeConstraint{.reg = R3}` → seed = {R3}
- Assertions with no register dependencies (e.g., `BoundedLoopCount`) produce an
  empty seed; the algorithm enters **conservative mode**, including all reachable
  labels to show the loop structure and control flow leading to the failure.

### Step 2: Failing Instruction Reads

The failing instruction itself always contributes. For example, the store
`*(u64 *)(r3 + 32) = r8` reads R3 and R8 but writes to memory, not registers.
Without special-casing, `instruction_contributes` would be false (no relevant
register is *written*). The algorithm forces `instruction_contributes = true` at
the failing label so that the instruction's read registers (R3, R8) enter the
relevance set.

### Step 3: Backward Traversal

Using a worklist, walk `cfg.parents_of(label)` for each relevant label.

**Transfer function** at each label:

```text
relevant_before = relevant_after
    - remove regs_written     (not relevant before their definition)
    - remove regs_clobbered   (killed without reading)
    + add regs_read           IF instruction_contributes
    - remove stack_written     (unless also in stack_read)
    + add stack_read           IF instruction_contributes
```

An instruction **contributes** when:
1. It writes to a relevant register or stack slot (data dependency), OR
2. It is a control-flow instruction (`Jmp` or `Assume`) that reads a relevant register
   (branch decisions that shape the path to the failure), OR
3. It is the failing instruction itself (step 2), OR
4. It is an immediate path guard (step 4 below).

Only contributing instructions are added to `slice_labels`; non-contributing labels
are still added to `visited` for traversal but are excluded from the output.

### Step 4: Immediate Path Guards

When the backward walk encounters an `Assume` instruction that is a **direct
predecessor** of the failing label, it is treated as always-contributing. Assumes
are path conditions that constrain which abstract states reach the failing point —
they are causally relevant even if they don't write to data-relevant registers.

For example, `assume r4 w== 0` at edge 229:230 guards the failing store at label
230. The algorithm detects this by checking whether the current label is in
`cfg.parents_of(failing_label)`. When it is, the Assume's read registers (R4) are
added to the relevance set, which pulls in the upstream definition of R4.

This is intentionally conservative: only the *immediate* guard of the failing label
is treated specially. Other `Assume` and `Jmp` instructions are included only when
they read registers that are already relevant (condition 2 above). Expanding to all
control-flow instructions regardless of relevance would cause the slice to explode.

### Step 5: Merge on Revisit

If a label is visited multiple times (due to control-flow joins), the relevance
sets are unioned. If no new registers or stack offsets are added, the label is
skipped to avoid redundant work.

### Step 6: Step Limit

The worklist stops after `max_steps` items (default: 200, configurable via
`--failure-slice-depth`). This prevents unbounded traversal on very large programs
while still reaching relevant definitions that may be dozens of blocks upstream.

### Step 7: Join-Point Expansion

After the worklist completes, the algorithm scans all traversed labels for join
points (labels with ≥2 CFG predecessors where at least one predecessor is already in
the slice). All predecessors of such join points are added to the slice — even if
the worklist never reached them — so the per-predecessor invariant display is
complete. This post-processing step ensures converging paths are visible without
requiring the worklist budget to be large enough to traverse all branches.

## Join-Point Context

When the backward walk crosses a join point (a label with ≥ 2 predecessors in the
slice), the printer emits per-predecessor post-invariants. This directly surfaces
the §4.11 "Lost Correlations" pattern from the
[LLM Context Document](llm-context.md):

```text
229:
  --- join point: per-predecessor state ---
  from 227: [packet_size=62, r4.svalue=0]
  from 228: [packet_size=34, r4.svalue=-22]
  --- end join point ---
```

The merged state `packet_size=34, r4.svalue=[-22,0]` loses the correlation between
the flag variable (R4) and the packet size. The per-predecessor display makes this
loss explicit without requiring the reader to reconstruct it from the full CFG.

## Control-Flow Summary

The `[CONTROL FLOW]` section provides a compact branch-path skeleton through the
slice. Each label is listed in sorted order with annotations for branch instructions:

```text
[CONTROL FLOW] 209, 210, ..., {225:226 (assume r1 <= r2) | 225:228 (assume r1 > r2)} -> 229 (if r4 != 0), 229:230 (assume r4 == 0), 230 FAIL
```

Labels are comma-separated. At join points (labels with ≥2 predecessors in the slice),
converging predecessors are grouped as `{pred1 | pred2} -> join_label`.

This tells the reader the high-level story: which branches were taken, where paths
converge, and which assumptions hold — all in a single line.

## Filtering Details

### Assertion Filtering

Only assertions involving relevant registers are shown. Uses
`extract_assertion_registers()` to determine which registers an assertion depends on.

### Invariant Filtering

The `RelevantState::is_relevant_constraint()` method filters constraint strings:

- **Simple constraints**: `r1.type=number` — shown if R1 is relevant
- **Relational constraints**: `r1.svalue-r8.svalue<=100` — shown if R1 OR R8 is relevant
- **Stack constraints**: `s[4088...4095].type=ctx` — shown if stack offset overlaps
- **Global context**: `packet_size`, `meta_offset` — always shown

**Design note:** Filtering is performed on serialized constraint strings at the output
stream level rather than by querying the abstract domain directly. This is because:

1. The abstract domain (`EbpfDomain`) is available in the invariant map, but its
   serialization produces a flat list of constraint strings — there is no API to
   enumerate "constraints involving register R1" without parsing the output.
2. The abstract domain is a reduced product of multiple numeric domains (intervals,
   congruences, linear constraints) — extracting "which registers does this constraint
   touch" would require traversing each domain's internal representation.
3. The constraint string format is stable (`rN.field`, `s[offset...offset]`) making
   regex matching reliable without deep Crab knowledge.

## Data Structures

### InstructionDeps

```cpp
struct InstructionDeps {
    std::set<Reg> regs_read;
    std::set<Reg> regs_written;
    std::set<Reg> regs_clobbered;    // Killed without reading (e.g., helper call)
    std::set<int64_t> stack_read;    // Concrete stack offsets
    std::set<int64_t> stack_written;
};
```

### RelevantState

```cpp
struct RelevantState {
    std::set<Reg> registers;
    std::set<int64_t> stack_offsets;

    // Check if a constraint string involves a relevant register
    bool is_relevant_constraint(const std::string& constraint) const;
};
```

### FailureSlice

```cpp
struct FailureSlice {
    Label failing_label;
    VerificationError error;
    std::map<Label, RelevantState> relevance;  // Per-label relevant state

    std::set<Label> impacted_labels() const;   // Keys of relevance map
};
```

## API

### Enabling Dependency Collection

Set the flag before verification:

```cpp
ebpf_verifier_options_t options;
options.verbosity_opts.collect_instruction_deps = true;
```

### Computing Slices

After verification fails:

```cpp
AnalysisResult result = analyze(prog);
if (result.failed) {
    // max_steps: worklist step limit (default 200)
    // max_slices: number of failures to process (0 = all, 1 = first only)
    std::vector<FailureSlice> slices = result.compute_failure_slices(
        prog, /*max_steps=*/200, /*max_slices=*/1);

    for (const auto& slice : slices) {
        // slice.failing_label  — where the error occurred
        // slice.error          — the verification error
        // slice.impacted_labels() — set of labels in the slice
        // slice.relevance      — per-label relevant registers/stack
    }
}
```

### Printing Slices

```cpp
// simplify: collapse basic blocks (default false for slices)
// compact: skip invariants entirely (default false)
print_failure_slices(std::cout, prog, /*simplify=*/false, result, slices);
```

### Invariant Filtering

Use the stream manipulator to filter invariant output:

```cpp
// Set filter — only show constraints involving these registers
os << invariant_filter(&relevant_state) << domain;

// Clear filter
os << invariant_filter(nullptr) << domain;
```

## Examples

### Simple Case: Null Pointer After Map Lookup

```bash
./bin/check ebpf-samples/build/nullmapref.o test --failure-slice
```

```text
=== Failure Slice 1 of 1 ===

[ERROR] Possible null access (valid_access(r0.offset, width=4) for write)
[LOCATION] 7
[RELEVANT REGISTERS] r0
[SLICE SIZE] 6 program points
[CONTROL FLOW] 0, 2, 3, 4, 6, 7 FAIL
```

The slice traces R0 from the failing store back through `bpf_map_lookup_elem` (which
returns a nullable pointer) to the map setup instructions. The key invariant at the
failure point is `r0.svalue=[0, 2147418112]` — the lower bound of 0 means NULL is
possible.

### Complex Case: Lost Correlations

```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/20 --failure-slice
```

```text
=== Failure Slice 1 of 1 ===

[ERROR] Upper bound must be at most packet_size (valid_access(r3.offset+32, width=8) for write)
[LOCATION] 230
[RELEVANT REGISTERS] r3, r4
[SLICE SIZE] 14 program points
[CONTROL FLOW] 209, 210, ..., {225:226 | 225:228 (assume r1 > r2)} -> 229 (if r4 != 0), 229:230 (assume r4 == 0), 230 FAIL
```

From a 240-instruction program with 2003 lines of verbose output, the slice extracts
14 instructions in 335 lines. The slice shows:
- R3's definition chain (packet pointer + offset)
- `225:228: assume r1 > r2` — the branch where the packet is too small
- `228: r4 = -22` — the error code assigned on the short-packet path
- `229:230: assume r4 w== 0` — the path guard that should prevent reaching the store
- `230: *(u64 *)(r3 + 32) = r8` — the failing store

The key diagnostic insight: the verifier loses the correlation between R4 (the error
flag) and `packet_size` at the join point (block 229), so `assume r4 == 0` does not
narrow `packet_size` — a §4.11 "Lost Correlations" pattern.

## Performance

Output size comparison across test cases:

| Program | `-v` lines | `--failure-slice` lines | Slice instructions | Reduction |
|---------|:----------:|:-----------------------:|:------------------:|:---------:|
| nullmapref.o (10 instrs) | 39 | 132 | 6 | N/A |
| packet_overflow.o (8 instrs) | 68 | 79 | 4 | N/A |
| divzero.o (18 instrs) | 61 | 152 | 8 | N/A |
| bpf_xdp_dsr_linux.o 2/20 (240 instrs) | 2,003 | 335 | 14 | **83%** |

For small programs (e.g., nullmapref.o), the slice output can be *larger* than `-v`
because of section headers and per-instruction filtered invariants — this is expected
and not a regression. The real value is on large programs where the slice provides
dramatic reduction while preserving all causally relevant information.

## Limitations

- **Counter-based errors** (e.g., "Loop counter is too large" from `--termination`)
  have no register dependencies; the slicer uses conservative mode to include all
  reachable labels, showing the loop structure and control flow but without
  register-level causal filtering.
- **Verification passes** (exit code 0) produce no failure slices — there is nothing
  to slice.
- **Control-flow inclusion is relevance-gated**: `Jmp` and `Assume` instructions are
  included when they read registers that are already relevant. This means branches on
  *unrelated* registers (that happen to be on the path) are excluded, keeping slices
  small — but it may omit dominating branches several blocks away whose condition
  registers are not in the relevance set.
- **Invariant verbosity**: Filtered invariants still include all matching constraints
  for relevant registers. For registers that participate in many relational constraints,
  this can still produce substantial output.

## Integration with LLM Context

The [LLM Context Document](../docs/llm-context.md) provides patterns for interpreting
verification failures. When using failure slices with an LLM:

1. Run with `--failure-slice` to get minimal output
2. The `[ERROR]` and `[RELEVANT REGISTERS]` sections identify the assertion and registers
3. The `[CONTROL FLOW]` section shows the branch-path skeleton
4. The `[CAUSAL TRACE]` shows filtered invariants at each contributing instruction
5. Match the error message to patterns in Section 4 of the LLM context doc
6. The fix typically involves the earliest instruction in the slice or a missing guard

## Files

| File | Description |
|------|-------------|
| `src/result.hpp` | `FailureSlice`, `RelevantState`, `InstructionDeps`, `invariant_filter` |
| `src/result.cpp` | `compute_failure_slices()`, `extract_instruction_deps()`, `extract_assertion_registers()`, `is_relevant_constraint()` |
| `src/printing.cpp` | `print_failure_slices()`, `print_invariants_filtered()`, join-point context, control-flow summary |
| `src/fwd_analyzer.cpp` | Hooks to populate deps during forward analysis |
| `src/ir/parse.cpp` | Invariant filter integration in `operator<<(StringInvariant)` |
| `src/config.hpp` | `collect_instruction_deps` flag |
| `src/main/check.cpp` | `--failure-slice` and `--failure-slice-depth` CLI flags |
