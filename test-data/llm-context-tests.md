# LLM Context Document Test Cases

This file contains test cases for validating that `docs/llm-context.md` enables accurate diagnosis of verification failures.

## Prerequisites

The test samples are in `ebpf-samples/build/`. These are built from source files in `ebpf-samples/src/` by configuring and building the `ebpf-samples` sub-project explicitly:

```bash
cmake -S ebpf-samples -B ebpf-samples/cmake-build -DCMAKE_BUILD_TYPE=Release
cmake --build ebpf-samples/cmake-build
```

Other samples are pre-built in `ebpf-samples/cilium/`, `ebpf-samples/prototype-kernel/`, `ebpf-samples/linux/`, and `ebpf-samples/cilium-core/`.

## How to Test

In a GitHub Copilot CLI session:

```text
Using docs/llm-context.md, run ./bin/check <sample> <section> -v and diagnose the failure.
```

The LLM should:
1. Identify the correct failure pattern from the document
2. Explain the root cause by reading the pre-invariant
3. Suggest the correct fix

## Automated Regression Prompt

The following prompt can be used in a Copilot CLI session to execute all test cases automatically:

```text
Read docs/llm-context.md for diagnostic patterns. Then for each test case in
test-data/llm-context-tests.md, run the specified command and diagnose the failure.

For each test case:
1. Run the command shown
2. Identify the §4.X pattern from llm-context.md that matches the error
3. Read the pre-invariant at the failing label to confirm the root cause
4. Compare your diagnosis against the expected pattern and key invariant

Report results as a table:
| Test | Expected Pattern | Actual Pattern | Key Invariant Found | PASS/FAIL |

A test PASSES when:
- The correct §4.X pattern is identified
- The key invariant from the expected values is present in the output
- The root cause explanation is consistent with the expected fix

Skip any test marked as SLOW unless specifically requested.
```

## Test Cases — Small Programs

### Test 1: Null Pointer After Map Lookup

```bash
./bin/check ebpf-samples/build/nullmapref.o test -v
```
**Expected error**: `Possible null access (valid_access(r0.offset, width=4) for write)`
**Pattern**: 4.4 - Null Pointer After Map Lookup
**Key invariant**: `r0.svalue=[0, 2147418112]` - lower bound of 0 means NULL is possible
**Fix**: Add null check after `bpf_map_lookup_elem`

---

### Test 2: Unbounded Packet Access
```bash
./bin/check ebpf-samples/build/packet_overflow.o xdp -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r2.offset, width=4) for read)`
**Pattern**: 4.2 - Unbounded Packet Access
**Key invariant**: `packet_size=0` - no bounds check established minimum packet size
**Fix**: Add `if (data + N > data_end)` check before access

---

### Test 3: Uninitialized Stack Memory
```bash
./bin/check ebpf-samples/build/ringbuf_uninit.o .text -v
```
**Expected error**: `Stack content is not numeric (valid_access(r2.offset, width=r3) for read)`
**Pattern**: 4.9 variant - stack buffer not initialized with numeric data before helper call
**Key invariant**: `Stack: Numbers -> {}` - no stack bytes marked as numeric
**Fix**: Initialize stack buffer before passing to helper

---

### Test 4: Pointer Exposure to Map
```bash
./bin/check ebpf-samples/build/exposeptr.o .text -v
```
**Expected error**: `Illegal map update with a non-numerical value [4088-4096) (within(r3:value_size(r1)))`
**Pattern**: 4.9 - Map Key/Value Size Mismatch (non-numeric variant)
**Key invariant**: `s[4088...4095].type=ctx` - context pointer stored on stack, passed as map value
**Fix**: Store numeric data only in maps (security: prevents kernel address leaks)

---

### Test 5: Nonzero Context Offset
```bash
./bin/check ebpf-samples/build/ctxoffset.o sockops -v
```
**Expected error**: `Nonzero context offset (r1.ctx_offset == 0)`
**Pattern**: 4.10 - Context Field Bounds Violation (ctx_offset variant)
**Key invariant**: `r1.ctx_offset=8` - context pointer was modified before helper call
**Fix**: Pass original unmodified context pointer to helpers

---

### Test 6: Map Value Overrun
```bash
./bin/check ebpf-samples/build/mapvalue-overrun.o .text -v
```
**Expected error**: `Upper bound must be at most r1.shared_region_size (valid_access(r1.offset, width=8) for read)`
**Pattern**: Similar to 4.2 but for shared memory
**Key invariant**: `r1.shared_region_size=4` - map value is 4 bytes, but reading 8
**Fix**: Match read width to map value size, or increase map value size

---

### Test 7: Pointer Arithmetic with Non-Number
```bash
./bin/check ebpf-samples/build/ptr_arith.o xdp -v
```
**Expected error**: `Invalid type (r<N>.type == number)`
**Pattern**: 4.6 - Pointer Arithmetic with Non-Number
**Key invariant**: Register used in arithmetic has `type=packet` instead of `type=number`
**Fix**: Only add/subtract numeric values to/from pointers

---

### Test 8: Division by Zero
```bash
./bin/check ebpf-samples/build/divzero.o test -v --no-division-by-zero
```
**Expected error**: `Possible division by zero`
**Pattern**: 4.8 - Division by Zero
**Key invariant**: Divisor register has `svalue=[0, ...]` - lower bound includes 0
**Fix**: Add check `if (divisor != 0)` before division
**Note**: Requires `--no-division-by-zero` flag because the verifier allows division by zero by default (`--allow-division-by-zero`); the negated flag enables the check

---

### Test 9: Infinite Loop (Unbounded)
```bash
./bin/check ebpf-samples/build/infinite_loop.o test -v --termination
```
**Expected error**: `Could not prove termination` or loop counter shows `[1, +oo]`
**Pattern**: 4.7 - Infinite Loop / Termination Failure
**Key invariant**: Loop bound comes from map value with unbounded range `[0, UINT32_MAX]`
**Fix**: Use compile-time constant bounds or restructure loop
**Note**: Requires `--termination` flag (termination checking is disabled by default)

---

### Test 10: Bounded Loop (Compiler Transformation)
```bash
./bin/check ebpf-samples/build/bounded_loop.o test -v --termination
```
**Expected error**: `Could not prove termination`
**Pattern**: 4.7 - Infinite Loop / Termination Failure (compiler transformation variant)
**Key invariant**: Clang transforms `i < 1000` to `i != 1000`; verifier can't prove equality will be reached
**Fix**: This is a verifier limitation; the loop is actually bounded but unprovable
**Note**: Requires `--termination` flag (termination checking is disabled by default)

---

### Test 11: Lost Correlations in Computed Branches
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/20 -v
```
**Expected error**: `Upper bound must be at most packet_size`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Branch on computed value (e.g., `r4.svalue=[-22, 0]`) but packet offset range remains wide
**Fix**: Use direct pointer comparisons instead of computed intermediates (verifier limitation)

---

### Test 12: Bad Map Pointer Type
```bash
./bin/check ebpf-samples/build/badmapptr.o test -v
```
**Expected error**: `Invalid type (r1.type in {number, ctx, stack, packet, shared})`
**Pattern**: 4.6 - Type Mismatch (using map_fd where a pointer is expected)
**Key invariant**: `r1.type=map_fd` — a map file descriptor was passed where the helper expects a memory pointer
**Fix**: Pass a pointer to the map value (from `bpf_map_lookup_elem`), not the map fd itself

---

### Test 13: Bad Helper Call (Stack Overflow)
```bash
./bin/check ebpf-samples/build/badhelpercall.o .text -v
```
**Expected error**: `Upper bound must be at most EBPF_TOTAL_STACK_SIZE (valid_access(r1.offset, width=r2) for write)`
**Pattern**: 4.3 - Stack Out-of-Bounds Access
**Key invariant**: `r1.stack_offset=4095` with `r2.svalue=20` — writing 20 bytes at stack offset 4095 exceeds EBPF_TOTAL_STACK_SIZE (4096)
**Fix**: Ensure stack pointer + access width stays within the current 512-byte stack frame (absolute offsets 3584–4096 for the main frame)

---

### Test 14: Dependent Packet Read (Lost Correlation)
```bash
./bin/check ebpf-samples/build/dependent_read.o xdp -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r1.offset, width=4) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: At the failing label, `packet_size=1` but reading 4 bytes. The bounds check path sets `r5=1` with `packet_size=4`, but the join with the non-checked path (`r5=0`, `packet_size=0`) weakens `packet_size` to 1. The `assume r5 != 0` guard does not recover the correlation.
**Fix**: Use direct `if (data + 4 > data_end)` check immediately before the read (verifier limitation with indirect guards)

---

### Test 15: Pointer Exposure to Map (Key Variant)
```bash
./bin/check ebpf-samples/build/exposeptr2.o .text -v
```
**Expected error**: `Illegal map update with a non-numerical value [4088-4096) (within(r2:key_size(r1)))`
**Pattern**: 4.9 - Map Key/Value Size Mismatch (non-numeric variant)
**Key invariant**: `s[4088...4095].type=ctx` — context pointer stored on stack, passed as map key
**Fix**: Store only numeric data in map keys (security: prevents kernel address leaks)

---

### Test 16: Stale Packet Pointer After Reallocation
```bash
./bin/check ebpf-samples/build/packet_reallocate.o socket_filter -v
```
**Expected error**: `Invalid type (r7.type in {ctx, stack, packet, shared})`
**Pattern**: 4.12 - Stale Pointer After Reallocation
**Key invariant**: `r7.type=packet` — r7 held a packet pointer before a helper call that may reallocate the packet buffer; after the call, the pointer is invalidated
**Fix**: Re-derive packet pointers from `ctx->data` / `ctx->data_end` after any helper call that may resize the packet

---

### Test 17: Wrong Map Type for Tail Call
```bash
./bin/check ebpf-samples/build/tail_call_bad.o xdp_prog -v
```
**Expected error**: `Invalid type (r2.type == map_fd_programs)`
**Pattern**: 4.6 - Type Mismatch
**Key invariant**: `r2.type=map_fd` but `bpf_tail_call` requires `r2.type=map_fd_programs` — a regular map was passed instead of a program array map
**Fix**: Use a `BPF_MAP_TYPE_PROG_ARRAY` map for tail calls

---

## Test Cases — Large Programs

### Test 18: Map Lookup After Conditional (xdp_ddos, xdp_prog)
```bash
./bin/check ebpf-samples/prototype-kernel/xdp_ddos01_blacklist_kern.o xdp_prog -v
```
**Expected error**: `Invalid type (r1.type == map_fd)`
**Pattern**: 4.11 - Lost Correlations (type domain)
**Key invariant**: `r1.type in {map_fd, number}` — after a conditional, one path sets r1 to a map_fd and the other leaves it as number; the join produces a union type that fails the `map_fd` assertion
**Fix**: Restructure to ensure `bpf_map_lookup_elem` is only called when r1 is definitely a map_fd (move the call inside the branch)

---

### Test 19: Pointer Arithmetic Type Error (xdp_ddos, .text)
```bash
./bin/check ebpf-samples/prototype-kernel/xdp_ddos01_blacklist_kern.o .text -v
```
**Expected error**: `Invalid type (r2.type == number)`
**Pattern**: 4.6 - Pointer Arithmetic with Non-Number
**Key invariant**: r2 has a non-number type when used in arithmetic — the instruction expects a numeric operand
**Fix**: Ensure the register holds a numeric value before arithmetic operations

---

### Test 20: Map-in-Map Lookup Type
```bash
./bin/check ebpf-samples/linux/test_map_in_map_kern.o "kprobe/sys_connect" -v
```
**Expected error**: `Invalid type (r1.type == map_fd)`
**Pattern**: 4.11 - Lost Correlations (inner map lookup)
**Key invariant**: `r1.type=number` or `r1.type=shared` — after `bpf_map_lookup_elem` on an outer map, the result should be used as a map_fd for the inner lookup, but the verifier tracks it as number/shared
**Fix**: This is a verifier limitation with map-in-map support; the verifier does not currently track inner map fd types through lookups

---

### Test 21: Non-Numerical Map Key (bpf_sock)
```bash
./bin/check ebpf-samples/cilium-core/bpf_sock.o "cgroup/recvmsg6" -v
```
**Expected error**: `Illegal map update with a non-numerical value [4048-4072) (within(r2:key_size(r1)))`
**Pattern**: 4.9 - Map Key/Value Size Mismatch (non-numeric variant)
**Key invariant**: Stack region `[4048-4072)` contains bytes not proven numeric — some bytes in the map key buffer were not initialized with numeric values
**Fix**: Initialize all bytes of the map key structure before passing to map helper

---

### Test 22: Unbounded Packet Access (bpf_xdp core)
```bash
./bin/check ebpf-samples/cilium-core/bpf_xdp.o "xdp/entry" -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r5.offset, width=1) for read)`
**Pattern**: 4.11 - Lost Correlations
**Key invariant**: `packet_size=34` but `r5.packet_offset=34` — reading 1 byte at offset 34 needs `packet_size ≥ 35`; a bounds check on a different path established `packet_size=35` but the join lost it
**Fix**: Restructure bounds check to directly guard the failing access path

---

### Test 23: Cilium DSR — Packet Write (2/7)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/7 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=4) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: `packet_size` is too small for the packet offset — bounds check result communicated through computed value, correlation lost at join
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 24: Cilium DSR — Packet Write (2/10)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/10 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=2) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size at the access point
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 25: Cilium DSR — Packet Write (2/17)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/17 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=4) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size at the access point
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 26: Cilium DSR — Packet Read (2/18)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/18 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=2) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size at the access point
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 27: Cilium DSR — Packet Write (2/21)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/21 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=2) for write)`
**Pattern**: 4.2 - Unbounded Packet Access
**Key invariant**: `packet_size=12` but `r4.packet_offset=12` — writing 2 bytes at offset 12 needs `packet_size ≥ 14`
**Fix**: Add bounds check `if (data + 14 > data_end)` before the write

---

### Test 28: Cilium SNAT — Packet Read (2/7)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_snat_linux.o 2/7 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=4) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size — same pattern as DSR 2/7
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 29: Cilium SNAT — Packet Read (2/10)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_snat_linux.o 2/10 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=2) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size — same pattern as DSR 2/10
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 30: Cilium SNAT — Packet Read (2/17)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_snat_linux.o 2/17 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=4) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size — same pattern as DSR 2/17
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 31: Cilium SNAT — Packet Read (2/18)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_snat_linux.o 2/18 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=2) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size — same pattern as DSR 2/18
**Fix**: Verifier limitation with indirect bounds communication

---

## Test Cases — Large Programs (SLOW)

These tests take significantly longer to run. Skip unless specifically requested.

### Test 32: Cilium DSR — Packet Access (2/15) (SLOW)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/15 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r5.offset, width=4) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 33: Cilium DSR — Type Error (2/16) (SLOW)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/16 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r3.offset, width=2) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 34: Cilium DSR — Packet Access (2/19) (SLOW)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/19 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=4) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 35: Cilium DSR — Type Error (2/24) (SLOW)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_dsr_linux.o 2/24 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r5.offset, width=2) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 36: Cilium SNAT — Packet Access (2/15) (SLOW)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_snat_linux.o 2/15 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r5.offset, width=4) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 37: Cilium SNAT — Type Error (2/16) (SLOW)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_snat_linux.o 2/16 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r3.offset, width=2) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 38: Cilium SNAT — Packet Access (2/19) (SLOW)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_snat_linux.o 2/19 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r4.offset, width=4) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size
**Fix**: Verifier limitation with indirect bounds communication

---

### Test 39: Cilium SNAT — Type Error (2/24) (SLOW)
```bash
./bin/check ebpf-samples/cilium/bpf_xdp_snat_linux.o 2/24 -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r5.offset, width=2) for read)`
**Pattern**: 4.11 - Lost Correlations in Computed Branches
**Key invariant**: Packet offset exceeds proven packet_size
**Fix**: Verifier limitation with indirect bounds communication

---

## Results Summary

All 39 test cases should produce the expected errors when run against a Prevail build.
Tests 1–31 run in under a few seconds each. Tests 32–39 (SLOW) may take significantly longer.

When validated with an LLM using `docs/llm-context.md`, the LLM should correctly identify the §4.X pattern for each test case.

**Prevail build**: Run `git describe --tags --always --dirty` from the repository root to record the build used for validation.

## Pattern Coverage

| Pattern | Tests |
|---------|-------|
| 4.2 - Unbounded Packet Access | 2, 27 |
| 4.3 - Stack Out-of-Bounds Access | 13 |
| 4.4 - Null Pointer After Map Lookup | 1 |
| 4.6 - Type Mismatch | 7, 12, 17, 19 |
| 4.7 - Infinite Loop / Termination | 9, 10 |
| 4.8 - Division by Zero | 8 |
| 4.9 - Map Key/Value Non-Numeric | 3, 4, 15, 21 |
| 4.10 - Context Field Bounds Violation | 5 |
| 4.11 - Lost Correlations | 6, 11, 14, 18, 20, 22–26, 28–39 |
| 4.12 - Stale Pointer After Reallocation | 16 |
