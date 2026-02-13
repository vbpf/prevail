# eBPF Language Feature Support Matrix

## Scope

This document tracks **eBPF language feature support** in Prevail.

It is a support matrix, not a roadmap:

- `Supported` means the feature is implemented.
- Capability gating (platform/config/conformance group checks) is still `Supported`.
- `Not implemented` is used only for recognized features whose semantics are intentionally not implemented yet.
- `Invalid` is used for malformed encodings or malformed metadata.

## Baseline references

- Linux baseline: **Linux 6.18** (longterm; released **2025-11-30**).
- ISA baseline: **RFC 9669** (BPF ISA).
- Cross-ecosystem references:
  - eBPF-for-Windows `docs/isa-support.rst`
  - iovisor/uBPF README

## Status legend

- `Supported`
- `Supported (capability-gated)`
- `Partial`
- `Not implemented`
- `Invalid`

## Feature matrix

### 1) Core ISA

| Feature | Status | Notes / Evidence |
|---|---|---|
| ALU/ALU64 arithmetic and bitwise core ops | Supported | `src/ir/unmarshal.cpp` (`getAluOp`, `makeAluOp`) |
| Signed DIV/MOD variants via `offset==1` | Supported | `src/ir/unmarshal.cpp` |
| MOVSX ALU variants (8/16/32 sign-extend) | Supported | decode + transformer support |
| Endianness and bswap ops | Supported | `INST_ALU_OP_END` handling |
| Jumps and conditional branches (`JMP`/`JMP32`) | Supported | `makeJmp` |
| `JA32` immediate-offset form | Supported | `INST_OP_JA32` path |
| `CALL` helper by static ID (`src=0`) | Supported (capability-gated) | implemented; helper availability / prototype validated by platform tables |
| `CALL` local subprogram (`src=1`) | Supported | local call graph expansion in CFG builder |
| `CALLX` register-based call | Supported (capability-gated) | implemented; requires `callx` conformance group |
| `CALL src=2` (helper by BTF ID) | Not implemented | recognized as `CallBtf`, then rejected with explicit NIY diagnostic |
| `EXIT` | Supported | implemented |

### 2) Memory and load/store forms

| Feature | Status | Notes / Evidence |
|---|---|---|
| `LDX/ST/STX` memory width forms (B/H/W/DW) | Supported | `makeMemOp` |
| Legacy packet access (`LD_ABS`/`LD_IND`) | Supported (capability-gated) | implemented; requires `packet` conformance group |
| LDDW immediate (`src=0`) | Supported | `makeLddw` |
| LDDW map FD pseudo (`src=1`) | Supported | `LoadMapFd` + ELF reloc handling |
| LDDW map value pseudo (`src=2`) | Supported | `LoadMapAddress` + ELF reloc handling |
| LDDW pseudo `src=3..6` (`variable_addr`, `code_addr`, `map_by_idx`, `map_value_by_idx`) | Not implemented | recognized as `LoadPseudo`, then rejected with explicit NIY diagnostic |
| MEMSX sign-extending loads (`LDXSB/LDXSH/LDXSW`) | Supported | decode + signed-load semantics implemented |

### 3) Atomics

| Feature | Status | Notes / Evidence |
|---|---|---|
| Atomic add/or/and/xor (32/64) | Supported (capability-gated) | implemented; requires `atomic32` / `atomic64` groups |
| Atomic xchg / cmpxchg (32/64) | Partial | implemented; known precision limitations in conformance expectations |

### 4) Call model and helper typing

| Feature | Status | Notes / Evidence |
|---|---|---|
| Helper arg/return typing model | Supported (capability-gated) | implemented; availability and shape depend on platform tables |
| Helper marked unavailable in platform tables | Supported (capability-gated) | explicit verification rejection due to platform capability, not NIY semantics |
| BPF-to-BPF non-recursive local call expansion | Supported | CFG macro expansion + recursion/depth guards |
| Max call depth guard | Supported | `MAX_CALL_STACK_FRAMES` enforcement |

### 5) BTF/ELF language-relevant handling

| Feature | Status | Notes / Evidence |
|---|---|---|
| Unsupported/invalid BTF data rejection | Invalid | explicit `UnmarshalError` diagnostics in ELF loader |
| Unsupported/invalid CO-RE/BTF relocation rejection | Invalid | explicit `UnmarshalError` diagnostics in ELF loader |

## Current known limitations

1. `CALL src=2` semantics are not implemented yet.
2. LDDW pseudo `src=3..6` semantics are not implemented yet.
3. Atomic `cmpxchg` precision is conservative in some cases.

## Diagnostic semantics (current)

- `not implemented: ...` is reserved for true semantic NIY features.
- `rejected: ...` is used for capability/platform/config restrictions.
- malformed encodings/data fail as invalid input diagnostics.

## External references

- Linux kernel releases: https://www.kernel.org/releases.html
- RFC 9669 (BPF ISA): https://www.rfc-editor.org/rfc/rfc9669.html
- Linux verifier doc: https://www.kernel.org/doc/html/latest/bpf/verifier.html
- eBPF-for-Windows ISA support matrix: https://github.com/microsoft/ebpf-for-windows/blob/main/docs/isa-support.rst
- eBPF-for-Windows README: https://github.com/microsoft/ebpf-for-windows
- iovisor/uBPF README: https://github.com/iovisor/ubpf
