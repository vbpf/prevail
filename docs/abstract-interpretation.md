# Abstract Interpretation

This document explains the abstract interpretation framework used by Prevail.

## What is Abstract Interpretation?

Abstract interpretation is a theory of sound approximation of program semantics. Instead of executing a program with concrete values, we execute it with *abstract values* that represent sets of concrete values.

**Example**: Instead of tracking that `x = 5`, we might track that `x ∈ [0, 10]` (an interval).

### Key Properties

1. **Soundness**: If the abstract execution says a property holds, it holds for all concrete executions
2. **Over-approximation**: Abstract values may include more behaviors than actually possible
3. **Termination**: Guaranteed to terminate via widening operators

## Fixpoint Computation

The goal is to find program invariants—properties that hold at each program point across all possible executions.

### Forward Analysis

Prevail performs forward analysis starting from the program entry:

```
entry_state = { R1 = ctx_pointer, R10 = stack_pointer, ... }

for each instruction in execution order:
    pre_state = join(post_states of all predecessors)
    post_state = transfer(pre_state, instruction)
```

### The Fixpoint Problem

Loops create cycles in the CFG. Naive iteration might not terminate:

```
// This loop has unbounded iterations
while (x < 1000000) {
    x = x + 1;  // x keeps growing, intervals keep widening
}
```

### Widening and Narrowing

**Widening** (`∇`) accelerates convergence by jumping to a stable approximation:

```
[0,0] → [0,1] → [0,2] → ... 
       widening kicks in
[0,0] → [0,1] → [0,+∞]  // Stable after widening
```

**Narrowing** (`Δ`) recovers precision after widening:

```
[0,+∞] ∩ (x < 1000000) → [0,999999]  // Narrowing refines
```

### Iteration Strategy

Prevail uses interleaved widening/narrowing:

```cpp
// In fwd_analyzer.cpp
if (iteration < 2) {
    // Join without widening
    new_pre = old_pre | computed_pre;
} else if (iteration == 2) {
    // Apply widening
    new_pre = old_pre.widen(computed_pre);
} else {
    // Narrowing phase
    new_pre = old_pre & computed_pre.widen(old_pre);
}
```

## Weak Topological Ordering (WTO)

WTO is an ordering of CFG nodes that enables efficient fixpoint computation.

### The Problem with Naive Ordering

Consider this CFG:

```
    ┌───────────────┐
    │               ▼
1 → 2 → 3 → 4 → 5 → 6 → exit
        ▲       │
        └───────┘
```

There are two loops: (2) and (3,4,5). Naive iteration processes all nodes equally, but we should:
1. Stabilize inner loop (3,4,5) first
2. Then stabilize outer loop (2)

### WTO Representation

WTO represents this as nested components:

```
1 (2 (3 4 5) 6) exit

Where:
- (3 4 5) is an inner cycle with head 3
- (2 ... 6) is an outer cycle with head 2
```

### Bourdoncle's Algorithm

**File**: `src/cfg/wto.cpp`

The algorithm:
1. Compute strongly connected components (SCCs)
2. For each SCC, identify the head (entry point)
3. Recursively decompose the SCC minus the head
4. Produce a hierarchical representation

```cpp
WtoBuilder::Component(vertex v) {
    PartitionElement partition;
    for (each successor u of v) {
        if (not visited u) {
            visit(u);
            if (dfn[u] <= head[v]) {
                head[v] = dfn[u];
                partition.push_back(u);
            }
        }
    }
    if (head[v] == dfn[v]) {
        // v is the head of an SCC
        if (partition not empty) {
            // Recursive decomposition
            for (u in partition)
                Component(u);
        }
    }
}
```

### WTO Nesting

Each node knows its nesting depth—the loop heads that contain it:

```cpp
struct WtoNesting {
    std::vector<Label> heads;  // Containing loop heads, innermost first
};
```

This enables:
- Widening only at loop heads
- Controlled iteration of nested loops

## Domain Operations

### Lattice Structure

Abstract domains form a lattice:

```
        ⊤ (top = no information)
       / \
      /   \
   [0,10] [5,15]
      \   /
       \ /
      [5,10]
       / \
      /   \
    [5,5] [10,10]
       \ /
        ⊥ (bottom = unreachable)
```

### Join (⊔)

Combines information from multiple paths:

```cpp
EbpfDomain operator|(const EbpfDomain& a, const EbpfDomain& b) {
    // Result must include all behaviors of both a and b
    return EbpfDomain{
        a.rcp | b.rcp,      // Join type-numeric domain
        a.stack | b.stack   // Join array domain
    };
}
```

### Meet (⊓)

Refines information (intersection):

```cpp
EbpfDomain operator&(const EbpfDomain& a, const EbpfDomain& b) {
    // Result must satisfy both a and b
    return EbpfDomain{
        a.rcp & b.rcp,
        a.stack & b.stack
    };
}
```

### Ordering (⊑)

Checks if one state is more precise than another:

```cpp
bool operator<=(const EbpfDomain& a, const EbpfDomain& b) {
    // a is more precise if it represents fewer concrete states
    return a.rcp <= b.rcp && a.stack <= b.stack;
}
```

## Transfer Functions

Transfer functions model how instructions affect abstract state.

### Example: Addition

```cpp
void EbpfTransformer::operator()(const Bin& bin) {
    if (bin.op == Bin::Op::ADD) {
        // dst.svalue = dst.svalue + src.svalue
        // Also update uvalue with wrapping arithmetic
        // If either is a pointer, update offset instead
    }
}
```

### Example: Memory Load

```cpp
void EbpfTransformer::do_load(const Mem& mem, const Reg& data_reg) {
    Type ptr_type = inv.get_type(mem.access.basereg);
    
    if (ptr_type == T_STACK) {
        // Read from array domain
        inv.stack.load(data_reg, offset, width);
    } else if (ptr_type == T_CTX) {
        // Read from context - result is unknown but bounded
        inv.havoc(data_reg);
        inv.assume(data_reg.svalue >= ctx_field_min);
        inv.assume(data_reg.svalue <= ctx_field_max);
    }
}
```

## Assertion Checking

Safety properties are checked via domain entailment:

```cpp
void EbpfChecker::operator()(const ValidAccess& va) {
    if (va.access_type == AccessType::STACK) {
        // Check: stack_offset - STACK_SIZE <= access_offset
        // Check: access_offset + access_width <= 0
        if (!inv.entails(access_in_bounds)) {
            throw VerificationError("stack out of bounds");
        }
    }
}
```

### Entailment

`domain.entails(constraint)` returns true if all concrete states in the domain satisfy the constraint:

```cpp
bool NumAbsDomain::entails(Condition cond) {
    // Check if cond holds for all values in the domain
    // E.g., if domain says x ∈ [5, 10], then x >= 3 is entailed
}
```

## Convergence Guarantees

The analysis is guaranteed to terminate because:

1. **Finite height**: Abstract domains have finite ascending chains (or widening enforces this)
2. **Monotonic transfer**: Transfer functions are monotonic
3. **Widening**: Jumps to stable approximations after bounded iterations
4. **Iteration limit**: Maximum 2M narrowing iterations (safety bound)

## Example Analysis

```asm
; Program: Increment counter in context
mov r2, 0           ; r2 = 0
ldxw r3, [r1+0]     ; r3 = ctx->counter
add r3, r2          ; r3 = r3 + r2 (no change since r2=0)
stxw [r1+0], r3     ; ctx->counter = r3
mov r0, 0           ; return 0
exit
```

**Analysis trace**:

```
Entry:
  R1: type=CTX, ctx_offset=0
  R10: type=STACK, stack_offset=512

After mov r2, 0:
  R2: type=NUM, svalue=[0,0], uvalue=[0,0]

After ldxw r3, [r1+0]:
  [Check: ValidAccess(R1, offset=0, width=4)]
  R3: type=NUM, svalue=[-2^31, 2^31-1]  (unknown 32-bit)

After add r3, r2:
  R3: type=NUM, svalue=[-2^31, 2^31-1]  (unchanged, adding 0)

After stxw [r1+0], r3:
  [Check: ValidAccess(R1, offset=0, width=4)]
  [Check: ValidStore(R1, R3)]

After mov r0, 0:
  R0: type=NUM, svalue=[0,0]

Exit:
  Result: R0 ∈ [0, 0]
  Verification: PASS
```
