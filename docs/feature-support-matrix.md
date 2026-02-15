# eBPF Language Feature Support Matrix

## Scope

This document is an internal engineering reference for language-level eBPF feature support in Prevail.
It records implementation state in code. It is not a kernel-compatibility or runtime-enablement contract.

## Baseline

As of **2026-02-13**:

- Linux baseline reference: **Linux 6.18** (longterm; released **2025-11-30**)
- ISA baseline reference: **RFC 9669**

## Status Keys

- `Supported`: semantic handling is implemented in Prevail.
- `Partial`: semantic handling is implemented with known precision or behavior limits.
- `Not implemented`: instruction form is recognized, but semantic handling is intentionally absent.

Capability and configuration checks are described in `Notes / Evidence`; they do not change support status.

## Evidence Conventions

- Each matrix row includes at least one concrete code reference (file and symbol) for traceability.
- Diagnostics behavior is documented separately from support state.

## Matrix

### Core ISA

| Feature | Status | Notes / Evidence |
|---|---|---|
| ALU/ALU64 arithmetic and bitwise core ops | Supported | `src/ir/unmarshal.cpp`: `getAluOp`, `makeAluOp` |
| Signed DIV/MOD variants via `offset==1` | Supported | `src/ir/unmarshal.cpp`: `getAluOp` |
| MOVSX ALU variants (8/16/32 sign-extend) | Supported | `src/ir/unmarshal.cpp`: `getAluOp`; `src/crab/ebpf_transformer.cpp`: `operator()(const Bin&)` |
| Endianness and bswap ops | Supported | `src/ir/unmarshal.cpp`: `getAluOp` (`INST_ALU_OP_END`); `src/crab/ebpf_transformer.cpp`: `operator()(const Un&)` |
| Jumps and conditional branches (`JMP`/`JMP32`) | Supported | `src/ir/unmarshal.cpp`: `makeJmp`; `src/ir/cfg_builder.cpp`: `instruction_seq_to_cfg` |
| `JA32` immediate-offset form | Supported | `src/ir/unmarshal.cpp`: `makeJmp` (`INST_OP_JA32`) |
| `CALL` helper by static ID (`src=0`) | Supported | `src/ir/unmarshal.cpp`: `makeJmp`; `src/ir/cfg_builder.cpp`: `check_instruction_feature_support`; `src/platform.hpp`: `get_helper_prototype`, `is_helper_usable` |
| `CALL` local subprogram (`src=1`) | Supported | `src/ir/unmarshal.cpp`: `makeJmp`; `src/ir/cfg_builder.cpp` |
| `CALLX` register-based call | Supported | `src/ir/unmarshal.cpp`: `makeJmp`; `src/ir/cfg_builder.cpp`: `check_instruction_feature_support` |
| `CALL src=2` (helper by BTF ID) | Not implemented | `src/ir/unmarshal.cpp`: `makeJmp` (`CallBtf`); `src/ir/cfg_builder.cpp`: `check_instruction_feature_support` |
| `EXIT` | Supported | `src/ir/unmarshal.cpp`: `makeJmp` (`INST_OP_EXIT`) |

### Memory and Load/Store Forms

| Feature | Status | Notes / Evidence |
|---|---|---|
| `LDX/ST/STX` memory width forms (B/H/W/DW) | Supported | `src/ir/unmarshal.cpp`: `makeMemOp`; `src/ir/syntax.hpp`: `Mem` |
| Legacy packet access (`LD_ABS`/`LD_IND`) | Supported | `src/ir/unmarshal.cpp`; `src/ir/cfg_builder.cpp`: `check_instruction_feature_support` |
| LDDW immediate (`src=0`) | Supported | `src/ir/unmarshal.cpp`: `makeLddw` (`INST_LD_MODE_IMM`) |
| LDDW map FD pseudo (`src=1`) | Supported | `src/ir/unmarshal.cpp`: `makeLddw` (`INST_LD_MODE_MAP_FD`, `LoadMapFd`); `src/elf_loader.cpp`: `try_reloc` |
| LDDW map value pseudo (`src=2`) | Supported | `src/ir/unmarshal.cpp`: `makeLddw` (`INST_LD_MODE_MAP_VALUE`, `LoadMapAddress`); `src/elf_loader.cpp`: `try_reloc` |
| LDDW variable address pseudo (`src=3`) | Not implemented | `src/ir/unmarshal.cpp`: `makeLddw` (`INST_LD_MODE_VARIABLE_ADDR`, `LoadPseudo`); `src/ir/cfg_builder.cpp`: `check_instruction_feature_support` |
| LDDW code address pseudo (`src=4`) | Not implemented | `src/ir/unmarshal.cpp`: `makeLddw` (`INST_LD_MODE_CODE_ADDR`, `LoadPseudo`); `src/ir/cfg_builder.cpp`: `check_instruction_feature_support` |
| LDDW map-by-index pseudo (`src=5`) | Not implemented | `src/ir/unmarshal.cpp`: `makeLddw` (`INST_LD_MODE_MAP_BY_IDX`, `LoadPseudo`); `src/ir/cfg_builder.cpp`: `check_instruction_feature_support` |
| LDDW map-value-by-index pseudo (`src=6`) | Not implemented | `src/ir/unmarshal.cpp`: `makeLddw` (`INST_LD_MODE_MAP_VALUE_BY_IDX`, `LoadPseudo`); `src/ir/cfg_builder.cpp`: `check_instruction_feature_support` |
| MEMSX sign-extending loads (`LDXSB/LDXSH/LDXSW`) | Supported | `src/ir/unmarshal.cpp`: `makeMemOp` (`INST_MODE_MEMSX`); `src/crab/ebpf_transformer.cpp`: `operator()(const Mem&)`, `do_load_packet_or_shared` |

### Atomics

| Feature | Status | Notes / Evidence |
|---|---|---|
| Atomic add/or/and/xor (32/64) | Supported | `src/ir/unmarshal.cpp`: `getAtomicOp`, `makeMemOp`; `src/ir/cfg_builder.cpp`: `check_instruction_feature_support` |
| Atomic xchg / cmpxchg (32/64) | Supported | `src/ir/unmarshal.cpp`: `getAtomicOp`; `src/crab/ebpf_transformer.cpp` atomic handling. Shared memory is correctly havoc'd (volatile). Stack CMPXCHG is intentionally imprecise (havoc); precise modeling is not useful since atomics on thread-local memory have no real use case. |

### Call Model and Helper Typing

| Feature | Status | Notes / Evidence |
|---|---|---|
| Helper arg/return typing model | Supported | `src/ir/unmarshal.cpp`: `makeCall`; `src/platform.hpp`: `get_helper_prototype` |
| Helper unavailable in platform tables | Supported | `src/ir/unmarshal.cpp`: helper-unavailable path in `makeJmp`; `src/ir/cfg_builder.cpp`: `check_instruction_feature_support` |
| BPF-to-BPF non-recursive local call expansion | Supported | `src/ir/cfg_builder.cpp`; `src/elf_loader.cpp` |
| Maximum call depth guard | Supported | `src/ir/cfg_builder.cpp`: `MAX_CALL_STACK_FRAMES` |

### BTF/ELF Language-Relevant Handling

| Feature | Status | Notes / Evidence |
|---|---|---|
| BTF data handling | Supported | `src/elf_loader.cpp`: `parse_btf_section`; invalid data rejected as `UnmarshalError` |
| CO-RE/BTF relocation handling | Supported | `src/elf_loader.cpp`: `process_core_relocations`, `apply_core_relocation`; invalid/unsupported relocation data rejected as `UnmarshalError` |

## Diagnostics

- `not implemented: ...`: recognized instruction form with missing semantic implementation.
- `rejected: ...`: platform/capability/configuration restriction.
- Invalid instruction encodings and malformed metadata are rejected as invalid input (typically surfaced as `InvalidInstruction` or `UnmarshalError` during decode/load).

## References

- Linux kernel releases: https://www.kernel.org/releases.html
- RFC 9669 (BPF ISA): https://www.rfc-editor.org/rfc/rfc9669.html
- Linux verifier documentation: https://www.kernel.org/doc/html/latest/bpf/verifier.html
- eBPF-for-Windows ISA support matrix: https://github.com/microsoft/ebpf-for-windows/blob/main/docs/isa-support.rst
- eBPF-for-Windows README: https://github.com/microsoft/ebpf-for-windows
- iovisor/uBPF README: https://github.com/iovisor/ubpf
