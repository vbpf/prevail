# Architecture Overview

This document describes the high-level architecture of the Prevail eBPF verifier.

## Pipeline Overview

The verification process follows a linear pipeline:

```
ELF Binary → Unmarshal → Build CFG → Abstract Interpretation → Result
```

### Stage 1: ELF Loading and Unmarshalling

**Files**: `src/elf_loader.cpp`, `src/ir/asm_unmarshal.cpp`

1. **ELF Parsing**: Extract eBPF bytecode sections from ELF files
2. **Instruction Decoding**: Convert raw bytes to structured instructions
3. **Semantic Translation**: Map hardware opcodes to semantic IR

The unmarshaller handles:
- Instruction decoding (opcode, registers, immediate values)
- Wide instruction handling (64-bit immediates span two instructions)
- Endianness conversion
- Basic syntax validation

### Stage 2: CFG Construction

**Files**: `src/ir/cfg_builder.cpp`, `src/cfg/cfg.hpp`

The CFG builder transforms the linear instruction sequence into a control flow graph:

1. **Node Creation**: Each instruction becomes a labeled node
2. **Edge Creation**: Connect nodes based on control flow
3. **Assertion Generation**: Insert safety checks at appropriate points
4. **Function Inlining**: Inline local function calls with stack frame prefixes

Key transformations:
- Conditional jumps split into two paths with explicit `Assume` instructions
- Loop heads are identified for widening
- Exit nodes connect to a special exit label

### Stage 3: Abstract Interpretation

**Files**: `src/fwd_analyzer.cpp`, `src/crab/`

The core verification uses forward abstract interpretation:

1. **Initialize**: Start with entry state (context pointer in R1, stack in R10)
2. **Iterate**: Process nodes in weak topological order
3. **Transform**: Apply instruction semantics via `EbpfTransformer`
4. **Check**: Verify assertions via `EbpfChecker`
5. **Converge**: Apply widening/narrowing until fixpoint

### Stage 4: Result Generation

**Files**: `src/result.cpp`

The analysis produces:
- **Invariants**: Pre/post states at each program point
- **Errors**: List of safety violations
- **Exit value**: Range of possible return values in R0
- **Loop bounds**: Maximum observed loop iterations

## Component Details

### EbpfDomain (State Representation)

The abstract state combines multiple domains:

```
EbpfDomain = TypeToNumDomain × ArrayDomain
           = (TypeDomain × NumAbsDomain) × ArrayDomain
```

- **TypeDomain**: Tracks pointer types (CTX, STACK, PACKET, MAP, SHARED, NUM)
- **NumAbsDomain**: Tracks numeric constraints (intervals + difference bounds)
- **ArrayDomain**: Models stack memory as array of typed cells

### EbpfTransformer (Instruction Semantics)

Implements transfer functions for each instruction type:

| Instruction | Semantic Effect |
|-------------|-----------------|
| `Bin` (ADD, SUB, ...) | Update numeric constraints |
| `Mem` (load/store) | Read/write array domain |
| `Call` | Apply helper function contracts |
| `Assume` | Refine domain with branch condition |
| `Jmp` | No state change (control flow only) |

### EbpfChecker (Assertion Verification)

Verifies safety properties by checking domain entailment:

| Assertion | Property Checked |
|-----------|------------------|
| `ValidAccess` | Memory access within bounds |
| `ValidStore` | Type-correct store operation |
| `ValidDivisor` | Non-zero divisor |
| `ValidCall` | Correct helper signature |
| `BoundedLoopCount` | Loop iteration limit |

## Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         Program                                  │
│  ┌──────────┐  ┌──────────────────┐  ┌────────────────────┐     │
│  │   CFG    │  │  Instructions    │  │    Assertions      │     │
│  │ (graph)  │  │ (per-label map)  │  │  (per-label list)  │     │
│  └──────────┘  └──────────────────┘  └────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              InterleavedFwdFixpointIterator                      │
│                                                                  │
│  for each node in WTO order:                                     │
│    pre_state = join(post_states of predecessors)                 │
│    check_assertions(pre_state, node.assertions)                  │
│    post_state = transform(pre_state, node.instruction)           │
│    if iteration > threshold: apply widening/narrowing            │
│    store invariant(node) = { pre_state, post_state }             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AnalysisResult                              │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ invariants: Map<Label, {pre, error, post}>              │    │
│  │ failed: bool                                             │    │
│  │ max_loop_count: int                                      │    │
│  │ exit_value: Interval                                     │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### 1. Forward Analysis

Prevail uses forward (rather than backward) analysis because:
- eBPF programs have a single entry point
- Memory safety depends on tracking pointer provenance from entry
- Type information flows naturally forward

### 2. Composite Domain

The domain hierarchy enables:
- **Type-guided precision**: Different numeric tracking per pointer type
- **Efficient joins**: Type mismatches detected early
- **Modular extension**: New pointer types can be added

### 3. Weak Topological Ordering

WTO-based iteration provides:
- **Efficient convergence**: Widening applied only at loop heads
- **Nested loop handling**: Inner loops stabilize before outer
- **Deterministic order**: Reproducible analysis results

### 4. Assertion-Based Checking

Separating assertions from semantics enables:
- **Modular safety properties**: Easy to add new checks
- **Precise error reporting**: Knows exactly which property failed
- **Configurable strictness**: Can enable/disable specific checks

## Entry Points

### CLI Tool: `check`

**File**: `src/main/check.cpp`

```bash
./check <elf-file> <section>/<function> [options]
```

Options:
- `--domain`: Choose abstract domain (e.g., `zoneCrab`)
- `--no-simplify`: Don't merge basic blocks
- `--strict`: Require explicit map bounds

### Library API

```cpp
#include "ebpf_verifier.hpp"

// Load and verify
auto raw_progs = read_elf(filename, section, options, platform);
auto prog = Program::from_sequence(instructions, info, options);
auto result = analyze(prog);

// Check result
if (!result.failed) {
    // Program is safe
}
```

## Thread Safety

The verifier uses thread-local storage for:
- **Variable registry**: Maps variable names to indices
- **Global program counter**: Tracks current instruction during analysis

This allows multiple verification instances to run concurrently without interference.
