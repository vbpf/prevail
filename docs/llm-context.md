# LLM Context Document for Prevail eBPF Verifier

This document provides the context needed for an LLM to accurately diagnose eBPF verification failures when given a Prevail log output.

## 1. Overview

**Prevail** is a static verifier for eBPF programs that uses **abstract interpretation** to prove memory safety, type safety, and (optionally) termination without executing the code. Unlike the Linux kernel verifier that simulates execution, Prevail computes **invariants**—logical statements that hold at every program point regardless of input values.

### What Prevail Verifies

1. **Memory safety**: All reads/writes stay within valid memory regions (stack, packet, context, shared/map memory)
2. **Type safety**: Registers contain the expected types (numbers, pointers to specific regions)
3. **Pointer arithmetic**: Only numbers can be added to pointers; only compatible pointers can be subtracted
4. **Division safety**: Divisors are never zero (unless explicitly allowed)
5. **Helper function contracts**: Arguments match the expected types and bounds
6. **Termination** (optional): Loops have bounded iteration counts

### How Verification Works

1. **Parse** the eBPF program into a control-flow graph (CFG)
2. **Initialize** abstract state at entry (context pointer in r1, stack pointer in r10)
3. **Iterate** to a fixpoint using widening/narrowing to handle loops
4. **Check assertions** at each program point (memory access, type constraints, etc.)
5. **Report errors** when an assertion cannot be proven to hold

---

## 2. Understanding Verification Logs

Prevail logs show the abstract state at each program point. Here's how to interpret them.

### 2.1 Log Structure

When running `./bin/check <file> <section> -v`, the verbose output shows:

```text
Pre-invariant : [
    <register types>][
    <numeric constraints>]
Stack: Numbers -> {<byte ranges>}
<pc>:<instruction>
Post-invariant : [
    <register types>][
    <numeric constraints>]
Stack: Numbers -> {<byte ranges>}
```

On verification failure, you'll see:

```text
Verification error:
<Pre-invariant at failing instruction>
<pc>: <error message>
```

- **Pre-invariant**: The abstract state *before* executing the instruction
- **pc**: Program counter (instruction number within the section)
- **instruction**: The eBPF instruction in human-readable form
- **Post-invariant**: The abstract state *after* executing the instruction

### 2.2 Register State Format

Each register has multiple abstract properties:

| Property | Meaning |
|----------|---------|
| `r<N>.type` | Type: `number`, `ctx`, `stack`, `packet`, `shared`, `map_fd`, or `map_fd_programs` |
| `r<N>.svalue` | Signed value or interval `[min, max]` |
| `r<N>.uvalue` | Unsigned value or interval `[min, max]` |
| `r<N>.ctx_offset` | Offset within context struct (if type=ctx) |
| `r<N>.stack_offset` | Offset within stack (if type=stack) |
| `r<N>.packet_offset` | Offset within packet (if type=packet) |
| `r<N>.shared_offset` | Offset within shared memory (if type=shared) |
| `r<N>.shared_region_size` | Size of the shared region (for bounds checking) |
| `r<N>.stack_numeric_size` | Number of contiguous numeric bytes at stack location |
| `r<N>.map_fd` | Map file descriptor value (if type=map_fd) |

**Interval notation**: `[min, max]` means the value is constrained to that range. `[4098, 2147418112]` is a typical pointer address range.

**Relational constraints**: Entries like `r2.packet_offset=packet_size` indicate relationships between variables.

### 2.3 Stack State Format

Stack memory is tracked separately:

| Property | Meaning |
|----------|---------|
| `s[N...M].type` | Type of bytes N through M |
| `s[N...M].svalue` | Signed value stored at those bytes |
| `s[N...M].uvalue` | Unsigned value stored at those bytes |
| `s[N].ctx_offset` | If a pointer is stored, its ctx_offset |
| `s[N].packet_offset` | If a pointer is stored, its packet_offset |

**Stack Numbers summary**: The line `Stack: Numbers -> {[A...B], [C...D]}` shows which byte ranges are known to contain numeric (non-pointer) data. Empty `{}` means no stack bytes are proven numeric.

Stack offsets `N` in `s[N]` / `s[N...M]` are absolute byte offsets within the total eBPF stack (`0..EBPF_TOTAL_STACK_SIZE-1`). For a given program point, the active stack frame is the interval `[r10.stack_offset-EBPF_SUBPROGRAM_STACK_SIZE, r10.stack_offset)`.

### 2.4 Global State Variables

| Variable | Meaning |
|----------|---------|
| `meta_offset` | Offset of packet metadata (negative = before data pointer) |
| `packet_size` | Packet size constraint |
| `pc[N]` | Loop counter for basic block N (used in termination checking) |

### 2.5 Error Message Format

Errors follow this pattern:

```text
<pc>: <reason> (<assertion>)
```

Where:
- **pc**: The program counter (or `pc:target` for conditional jumps)
- **reason**: Human-readable explanation of the failure
- **assertion**: The formal assertion that failed

**Example errors**:

```text
0: Invalid type (r3.type in {number, ctx, stack, packet, shared})
1: Upper bound must be at most packet_size (valid_access(r1.offset, width=8) for write)
0 (counter): Loop counter is too large (pc[0] < 100000)
```

---

## 3. Glossary of Log Terms

### Types

| Term | Description |
|------|-------------|
| `number` | A scalar integer (not a pointer) |
| `ctx` | Pointer to program context structure (e.g., `xdp_md`, `sk_buff`) |
| `stack` | Pointer to stack memory (512 bytes per stack frame) |
| `packet` | Pointer to packet data |
| `shared` | Pointer to shared memory (e.g., map values) |
| `map_fd` | Map file descriptor (not directly dereferenceable) |
| `map_fd_programs` | Program array map FD |

### Type Groups

| Group | Members |
|-------|---------|
| `pointer` | ctx, stack, packet, shared |
| `singleton_ptr` | Pointers to unique memory regions (ctx, stack, packet) |
| `mem` | packet, stack, shared (memory that can be read/written) |
| `mem_or_num` | number, stack, packet, shared |
| `ptr_or_num` | number, ctx, stack, packet, shared (excluding map FD types) |

### Common Assertions

| Assertion | What It Checks |
|-----------|----------------|
| `valid_access(reg.offset, width=N) for read/write` | Memory access is within bounds |
| `r<N>.type in {types}` | Register has one of the listed types |
| `r<N>.type == number` | Register is a number (not a pointer) |
| `r<N> != 0` | Register is non-zero (for division) |
| `pc[N] < 100000` | Loop counter is within limit |
| `within(reg:key_size(map))` | Map key access is valid |

### Access Bounds Messages

| Message | Meaning |
|---------|---------|
| `Lower bound must be at least 0` | Offset is negative when it shouldn't be |
| `Upper bound must be at most X` | Access extends past end of region |
| `Lower bound must be at least meta_offset` | Packet access before metadata start |
| `Lower bound must be at least r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE` | Stack underflow |
| `Stack content is not numeric` | Reading non-numeric data from stack |
| `Possible null access` | Pointer might be NULL |
| `Nonzero context offset` | Context pointer was modified before passing to helper |

---

## 4. Common Failure Patterns

### 4.1 Uninitialized Register Use

**Symptom**: `Invalid type (r<N>.type in {number, ctx, stack, packet, shared})`

**Cause**: Using a register before it has been assigned a value.

**Example**:

```text
Pre-invariant:[r0.type=number, r0.svalue=1]
   0: r0 += r3
Error: 0: Invalid type (r3.type in {number, ctx, stack, packet, shared})
```

**Fix**: Initialize the register before use, or ensure it's passed as a parameter.

---

### 4.2 Unbounded Packet Access

**Symptom**: `Upper bound must be at most packet_size (valid_access(r<N>.offset, width=W) for read/write)`

**Cause**: Reading/writing packet data without first checking the bounds.

**Example**:

```text
Pre-invariant:[packet_size=[0, 65534], r1.type=packet, r1.packet_offset=0]
   0: r4 = *(u64 *)(r1 + 0)
Error: 0: Upper bound must be at most packet_size
```

**Fix**: Add a bounds check before the access:

```c
if (data + sizeof(__u64) > data_end) return XDP_DROP;
```

---

### 4.3 Stack Out-of-Bounds Access

**Symptom**: `Lower bound must be at least r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE`

**Cause**: Accessing stack memory beyond the allocated frame.

**Example**:

```text
Pre-invariant:[r10.type=stack, r10.stack_offset=1024]
   0: *(u8 *)(r10 - 513) = 0
Error: 0: Lower bound must be at least r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE
```

**Fix**: Keep stack accesses within -512 to -1 of r10, or reduce local variable size.

---

### 4.4 Null Pointer After Map Lookup

**Symptom**: `Possible null access (valid_access(...) for read/write)`

**Cause**: Using a map lookup result without checking for NULL.

**Example**:

```c
value = bpf_map_lookup_elem(&my_map, &key);
*value = 42;  // Error: value might be NULL
```

**Fix**: Check the return value:

```c
value = bpf_map_lookup_elem(&my_map, &key);
if (value) {
    *value = 42;
}
```

---

### 4.5 Type Mismatch (Number as Pointer)

**Symptom**: `Only pointers can be dereferenced (valid_access(...))`

**Cause**: Trying to dereference a register that contains a number instead of a pointer.

**Example**:

```text
Pre-invariant:[r1.type=number, r1.svalue=42]
   0: r2 = *(u64 *)(r1 + 0)
Error: 0: Only pointers can be dereferenced
```

**Fix**: Ensure the register contains a valid pointer type before dereferencing.

---

### 4.6 Type Mismatch

**Symptom**: Type mismatch errors such as `Only numbers can be added to pointers`, `Only pointers can be dereferenced`, `Invalid type (rN.type == ...)`, or `Invalid type for operation`.

**Cause**: Using a register with the wrong abstract type for a given operation—for example, adding a pointer to a pointer, dereferencing a number, passing a scalar where a pointer is expected, or using the wrong pointer subtype (e.g., `map_fd` where `map_fd_programs` is required for `bpf_tail_call`).

**Fix**: Check the pre-invariant types of all registers involved in the failing instruction and ensure they match the verifier's expectations (e.g., addends are numbers, dereferenced values are pointers, helper arguments have the required pointer/number types).

---

### 4.7 Infinite Loop / Termination Failure

**Symptom**: `Loop counter is too large (pc[N] < 100000)`

**Cause**: The verifier cannot prove the loop terminates within the iteration limit.

**Example**:

```text
Pre-invariant:[]
   0: r0 = 0
   1: if r0 < 1 goto <start>
Error: 0 (counter): Loop counter is too large (pc[0] < 100000)
```

**Causes**:
- No increment to the loop variable
- Infinite loop by design (always branches back)
- Bound check uses wrong comparison (e.g., `!=` instead of `<`)

**Fix**: Ensure loop has a clear termination condition with a bounded counter.

---

### 4.8 Division by Zero

**Symptom**: `Possible division by zero (r<N> != 0)`

**Cause**: The divisor register might be zero.

**Fix**: Add an explicit check before division:

```c
if (divisor != 0) {
    result = dividend / divisor;
}
```

---

### 4.9 Map Key/Value Size Mismatch

**Symptom**: `Illegal map update with a non-numerical value` or `Map key size is not singleton`

**Cause**: The pointer passed to map helper doesn't point to enough numeric bytes, or the key/value size doesn't match the map definition.

**Variant - Pointer Exposure**: If `s[N...M].type=ctx` (or other pointer type) appears in the stack range being used as a map value, the code is attempting to store a pointer into a map. This is a security violation—maps can only store numeric data.

**Fix**: Ensure the stack buffer used for key/value is properly sized and initialized with numeric data. Never store pointers in maps.

---

### 4.10 Context Field Bounds Violation

**Symptom**: `Upper bound must be at most <size>` for context access, or `Nonzero context offset (r<N>.ctx_offset == 0)`

**Cause**: Reading past the end of the context structure, or passing a modified context pointer to a helper that requires the original.

**Example**: XDP context is 20 bytes, accessing at offset 24 fails. Or adding an offset to the context pointer before passing it to a helper like `bpf_sock_map_update`.

**Fix**: Only access defined fields within the context structure. Pass unmodified context pointers to helpers that require `ctx_offset == 0`.

---

### 4.11 Lost Correlations in Computed Branches (Verifier Limitation)

**Symptom**: Access fails bounds check (e.g., `Upper bound must be at most packet_size`) even though a branch condition *should* guarantee safety.

**Red Flags**:
- Branch condition uses a register with a narrow computed range (e.g., `r3.svalue=[-22, 0]`)
- The offset register has a wide range that wasn't narrowed by the branch (e.g., `r4.packet_offset=[14, 74]`)
- Code appears to have a bounds check, but via an intermediate variable rather than direct pointer comparison

**Cause**: The verifier's abstract domain (difference-bound matrices) cannot track implications through intermediate computations. If code computes `r3 = (ptr + N) - data_end`, then `r3 <= 0` *implies* the access is safe—but this implication is not propagated back to narrow the pointer's offset range.

**Diagnosis**: This is a **verifier limitation**, not necessarily a code bug. The code may be correct, but the verifier cannot prove it.

**Fixes** (workarounds to help the verifier):
1. **Use direct pointer comparisons**: `if (ptr + N > data_end)` instead of computing into a temporary variable
2. **Duplicate the bounds check** closer to the access point so the verifier sees it directly
3. **Restructure control flow** so the safety implication is explicit in the branch structure rather than computed

**Example**: Instead of:

```c
int diff = (data + 8) - data_end;
if (diff > 0) return XDP_DROP;
val = *(u64 *)data;  // Verifier may not see that diff <= 0 implies safety
```

Use:

```c
if (data + 8 > data_end) return XDP_DROP;
val = *(u64 *)data;  // Verifier directly tracks the pointer comparison
```

---

### 4.12 Stale Pointer After Reallocation

**Symptom**: `Invalid type (rN.type in {ctx, stack, packet, shared})` after a helper call that may resize the packet buffer.

**Cause**: A register held a `packet` pointer before a helper call (e.g., `bpf_xdp_adjust_head`, `bpf_skb_change_head`) that can reallocate the packet buffer. After the call, all previously-derived packet pointers are invalidated by the verifier because the underlying memory may have moved.

**Fix**: Re-derive packet pointers from `ctx->data` / `ctx->data_end` after any helper call that may resize the packet buffer. Do not cache packet pointers across such calls.

---

### 4.13 Non-Numeric Stack Content

**Symptom**: `Stack content is not numeric (valid_access(r<N>.offset, width=W) for read)`

**Cause**: A helper function requires its argument to point to a stack buffer containing only numeric (non-pointer) data, but the verifier cannot prove that all bytes in the buffer are numeric. This typically happens when:
- The stack buffer was never initialized before being passed to a helper
- Only part of the buffer was written, leaving some bytes uninitialized
- A pointer was previously stored in the buffer region

**Example**:

```text
Pre-invariant:[
    r1.type=stack, r1.stack_offset=3584,
    r2.type=stack, r2.stack_offset=4088, r3.svalue=8]
Stack: Numbers -> {}
   5: r0 = bpf_ringbuf_output:?(r1, r2, r3, r4)
Error: 5: Stack content is not numeric (valid_access(r2.offset, width=r3) for read)
```

**Key diagnostic**: Check `Stack: Numbers -> {...}` in the pre-invariant. If the byte range being read is not listed, those bytes are not proven numeric.

**Fix**: Initialize all bytes of the stack buffer with numeric data before passing to the helper:

```c
__builtin_memset(buf, 0, sizeof(buf));
// Now pass buf to helper
```

---

## 5. LLM Reasoning Protocol

When diagnosing a Prevail verification failure:

### Step 1: Identify the Error

Look for lines matching the pattern `<pc>: <message> (<assertion>)`. Note:
- The program counter (pc) where the error occurs
- The assertion type (e.g., `valid_access`, `type in {...}`, etc.)
- The specific constraint that failed

### Step 2: Locate the Context

Find the pre-invariant just before the failing instruction. This shows the abstract state at that point.

### Step 3: Trace the Register/Variable

For the register(s) mentioned in the error:
1. Check its type in the pre-invariant
2. Check its value/offset constraints
3. Look for missing constraints (e.g., no `packet_size` bound)

### Step 4: Identify Missing Constraints

Common missing constraints:
- **For packet access**: `packet_size >= access_end` relationship is missing
- **For shared access**: `r<N>.svalue > 0` (null check) is missing
- **For stack access**: `stack_numeric_size` is too small
- **For loops**: No counter increment or wrong comparison

### Step 5: Trace Backwards

If the pre-invariant seems correct, trace backwards to find where:
- A required constraint was lost (widening in loops)
- A branch condition wasn't captured
- An initialization was skipped

### Step 6: Formulate the Fix

Typical fixes:
- **Add bounds check** before memory access
- **Add null check** after map lookup
- **Initialize registers** before use
- **Add loop bound** for termination
- **Cast/narrow types** appropriately

### Red Flags to Watch For

| Pattern | Likely Issue |
|---------|--------------|
| `r<N>.type` missing from invariant | Uninitialized register |
| `packet_size=[0, X]` without offset constraint | Missing bounds check |
| `pc[N]=[1, +oo]` | Possible infinite loop |
| `shared_region_size` not constrained | Map value size unknown |
| Type is `number` but being dereferenced | Wrong register or missing assignment |
| Branch on computed value + wide offset range persists | Lost correlation (verifier limitation, see 4.11) |

---

## 6. Extracting Additional Information

When analyzing failures, you may need more context. Here's how to request it:

### Verbose Output

Run with `-v` flag for verbose output showing invariants at each step:

```bash
./bin/run_yaml test-data/<file>.yaml "<test name>" -v
```

### Full Program Listing

Request the full disassembly to see surrounding instructions:

```bash
./bin/check <elf-file> <section> --asm <disasm-file>
```

### Specific Invariant

Ask the user to share:
1. The complete pre-invariant at the failing instruction
2. The 3-5 instructions leading up to the failure
3. Any branch conditions in the path

### Map/Context Definitions

For map-related errors, request:
- Map type (array, hash, etc.)
- Key size and value size
- Context structure definition

---

## 7. Version Information

- **Prevail Build Identifier**: From the repository root, run `git describe --tags --always --dirty` (or `git rev-parse HEAD`) to record the verifier build/commit.
- **Document Version**: 1.0
- **Last Updated**: 2026-02-10

---

## Appendix A: Quick Reference

### Register Conventions

| Register | Convention |
|----------|------------|
| r0 | Return value from helpers; final program return |
| r1-r5 | Function arguments (caller-saved) |
| r6-r9 | Callee-saved |
| r10 | Read-only stack frame pointer |

### Stack Layout

- Main program: offsets 0-511 (accessed as r10-1 through r10-512)
- Subprograms: additional 512 bytes per call depth
- Total: up to 4KB (8 frames × 512 bytes)

### Common Helper Patterns

```c
// Map lookup - always check for NULL
void *value = bpf_map_lookup_elem(&map, &key);
if (!value) return 0;

// Packet access - always check bounds
if (data + sizeof(struct hdr) > data_end) return XDP_DROP;

// Division - always check divisor
if (divisor == 0) return 0;
result = dividend / divisor;
```

---

## Appendix B: Extended Context for Advanced Diagnosis

### Path-Insensitive Semantics

Prevail uses a single abstract state per program point. All control-flow paths merge into this state.

**Key Properties:**
- No path-sensitive refinement
- Correlated conditions are not preserved
- Pointer and numeric constraints collapse at joins
- Loop bodies merge with their own entry state

**Example: Correlated Branch Collapse**

```c
if (x < 10) {
    y = x + 1;
}
if (y < 11) {
    // Linux: safe
    // Prevail: y = [-inf, +inf]
}
```

After the first if, Prevail merges the "taken" and "not taken" paths:
- y is either x+1 or uninitialized
- The join produces y = unknown

### Widening and Narrowing Behavior

Prevail applies widening to ensure termination of abstract interpretation.

**When Widening Occurs:**
- At loop headers
- When intervals grow across iterations
- When pointer offsets cannot be proven stable

**Effects:**
- Loop counters lose precision
- Pointer bounds become unbounded
- Relational constraints disappear

**Example:**
```c
for (i = 0; i < n; i++) {
    ptr = base + i;
}
```
After widening:
- i = [-inf, +inf]
- ptr = base + unknown

### Pointer Provenance Rules

Prevail tracks pointer provenance strictly:

- Pointers belong to regions: stack, map value, packet, shared memory
- Pointer-to-pointer storage collapses provenance
- Arithmetic must stay within the same region
- Subtracting pointers yields a number and destroys provenance

**Example: Storing a Stack Pointer**

```c
*(u64 *)buf = (u64)stack_ptr;
```

After this:
- The stored value is a number
- Reloading it yields a number, not a pointer
- Any use as a pointer fails

### Subprogram and Call-Frame Semantics

**Register Rules:**
- r1–r5: arguments
- r0: return value
- r6–r9: callee-saved
- r10: frame pointer (read-only)

**Stack Behavior:**
- Each subprogram has its own stack frame
- Stack offsets are validated per frame
- Returning merges the callee's exit state into the caller

**Common Failure:**
Using r6 as a pointer without reinitializing after a call.

### Helper Function Contracts

Prevail enforces helper contracts strictly.

**Contract Components:**
- Argument types (pointer, scalar, map handle)
- Required bounds
- Return type (pointer, scalar, nullable pointer)
- Side effects (packet size changes, map value lifetime)

**Example: bpf_map_lookup_elem**
- r1: map handle (scalar)
- r2: pointer to key (stack or packet)
- Returns:
  - pointer to map value (shared region), or
  - NULL

LLMs must check:
- key pointer validity
- key size
- map value pointer provenance

### Differences Between Linux and Prevail

Prevail is intentionally more conservative.

| Feature | Linux Verifier | Prevail |
|--------|----------------|---------|
| Path sensitivity | Yes | No |
| Relational constraints | Some | Yes (DBM), but lost at joins/widening |
| Loop unrolling | Aggressive | None |
| Pointer tracking | Fine-grained | Region-based |
| Stack modeling | Per-path | Merged |

LLMs must not assume Linux-accepted code will pass Prevail.

### Canonical Fix Patterns

**Loop Fixes:**
- Use fixed upper bounds
- Hoist bounds checks outside loops
- Avoid induction variables tied to pointer offsets

**Pointer Fixes:**
- Avoid storing pointers in memory
- Recompute pointers from base + constant offsets
- Use helper-returned pointers directly

**Map Access Fixes:**
- Validate key pointers explicitly
- Avoid pointer arithmetic on map values
- Copy map values to stack if needed

---

## Appendix C: Worked Diagnosis Example

**Scenario**: Unbounded packet read fails verification.

### The Error

```text
0: Upper bound must be at most packet_size (valid_access(r1.offset, width=8) for read)
```

### The Log

```text
Pre-invariant:[
    meta_offset=0,
    packet_size=[0, 65534],
    r1.packet_offset=0, r1.type=packet, r1.svalue=[4098, 2147418112]]
   0: r4 = *(u64 *)(r1 + 0)
```

### Diagnosis

1. **Error location**: PC 0, reading 8 bytes from `r1`
2. **Pre-invariant shows**: `r1.packet_offset=0`, `packet_size=[0, 65534]`
3. **The problem**: Access requires `0 + 8 <= packet_size`, but `packet_size` could be 0
4. **Missing constraint**: No bounds check establishes `packet_size >= 8`

### Fix

Add bounds check before access:

```c
if (data + 8 > data_end) return XDP_DROP;
// Now packet_size >= 8 is established
value = *(u64 *)data;
```
