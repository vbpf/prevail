# Changelog

## v0.2.3 (2026-05-28)

Soundness fixes, helper/kfunc validation, sleepable program support, and a
broad internal restructuring that removes thread-local globals and untangles
runtime semantics from presentation.
39 commits since v0.2.2.

### Soundness fixes

- Fix heap-buffer-overflow from non-instruction-aligned FUNC symbols (#1106).
- Add 8 missing `reallocate_packet` flags on packet-modifying helpers
  (`clone_redirect`, `l3_csum_replace`, `l4_csum_replace`, `lwt_push_encap`,
  `lwt_seg6_action`, `lwt_seg6_store_bytes`, `msg_pull_data`,
  `store_hdr_opt`); without the flag, stale packet pointers could be reused
  after the call (#1125).
- Tighten `ValidMapKeyValue` packet bound; inline bounds checks (#1100).
- Restore callee-saved registers via rename to preserve zone edges across
  subprogram returns.
- Fix `EbpfDomain::to_set()` returning top instead of bottom for unreachable
  states.
- Fix `get_map_inner_map_fd` comparing map type instead of `inner_map_fd`.
- Fix failure-slice filter losing `total_stack_size` (#1094).

### Platform modeling

- Add sleepable program support and `might_sleep` helper gating (#1136).
- Enforce map-function compatibility checks (#1127).
- Enforce `get_local_storage` flags argument must be zero (#1129).
- Mark inner map template descriptors in `EbpfMapDescriptor` (#1069).

### API

- Add `--version` flag (#1108).
- Classify errors as bugs vs runtime input errors (#1104).
- Split `PlatformSpec` from `ProgramEnvironment` (#1096).
- Remove `thread_local_options` and `thread_local_program_info`; pass options
  explicitly and make `Program` self-contained (#1091, #1092).
- Pass explicit `AnalysisContext`; treat `VariableRegistry` as a global
  service (#1088).
- Thread stack-cell registry through `AnalysisContext` (#1116), then move it
  into `ArrayDomain`.
- Thread `CallBtf::module` through kfunc resolution (#1114).
- Untangle test-helper string parsing from the production verifier API
  (#1115).
- Rename `ElfProgramInfo::invalid` to `reject_load` (#1043).
- Refactor printing API alongside the failure-slice fix (#1094).

### Internals

- Split runtime semantics from presentation/orchestration (#1101).
- Make `Call` composition explicit; centralize region semantics (#1097).
- Decompose `Program::from_sequence` into named preparation passes (#1081).
- Share helper/kfunc arg resolution; compact kfunc prototype table (#1102).
- Extract `Extrapolator` to own the fixpoint iteration policy.
- Use COW `shared_ptr` for per-domain cell registry.
- Make `svalue` a T_NUM-specific kind variable.
- Drive `setup_entry` `init_r1` from program metadata; decouple from
  `from_constraints`.
- Extract `compute_slice_from_label` from `compute_failure_slices` (#1061).
- C++23: use `std::unreachable()` instead of `assert(false)` (#1075).

### Infrastructure

- Document Ubuntu and compiler version requirements in README (#630).
- CMake: list library and test sources explicitly (#144).
- Coverage: exclude `src/test` from lcov report (#344).
- Bump `softprops/action-gh-release` from 2 to 3.

## v0.2.2 (2026-04-15)

### Bug fixes

- Fix spurious widening precision loss in `EbpfDomain` that rejected
  concretely-safe programs using numeric counters stored on the stack
  across loops (#1071). Regression from #916.

## v0.2.1 (2026-04-14)

Bug fixes, API enhancements, and infrastructure updates.
14 commits since v0.2.0.

### API

- Make stack size and call depth runtime parameters via `--stack-size`
  and `--max-call-stack-frames` CLI options (#1070).
- Add map name in `EbpfMapDescriptor` and make map-related functions
  public in `EbpfDomain` (#1066). Note: inner map template names may
  be misleading; see #1069.

### Bug fixes

- Fix stack numeric size lost through imprecise pointer stores (#1068).
- Fix `rewrite_extern_constant_load` crash on values exceeding int32
  range (#1054).
- Fix heap-buffer-overflow in legacy maps section parsing.
- Only use result from `get_helper_prototype` when valid.

### ELF loader

- Fix `load_elf` to support non-file istream paths and add regression
  tests (#1048).
- Add `.ksyms` kfunc relocation support.

### Infrastructure

- Upgrade to C++23.
- Bump Catch2 from v3.13.0 to v3.14.0.
- Bump external/bpf_conformance, external/libbtf.

## v0.2.0 (2026-02-22)

Major expansion of type system, platform modeling, and safety guarantees.
34 commits since v0.1.3.

### Type system

- Add T_SOCKET, T_BTF_ID, T_ALLOC_MEM, T_FUNC type encodings with
  propagation through helpers and return values (#1020).
- Callback target validation for T_FUNC (#1022).
- Allocation size tracking for T_ALLOC_MEM (ringbuf_reserve bounds) (#1022).

### Platform modeling

- Expand Linux platform tables: 200+ helpers with full ABI type classes,
  unaliased from 6 generic groups to per-helper signatures (#1021).
- Add table-driven kfunc (CALL src=2) resolution and validation (#1023).
- Model additional helper ABI classes and harden call semantics (#1024).
- Support LDDW pseudo-addr lowering and tail-call parity checks (#1019).
- Fix context descriptors for tracing, struct_ops, lsm, lirc_mode2,
  syscall, and netfilter program types; update all context struct sizes
  against kernel 6.14 uapi headers (#959).

### Soundness fixes

- Fix two soundness bugs: stale shared_region_size after ambiguous map
  lookup (OOB read) and stale caller-saved registers after subprogram
  return (use-after-free) (#1028).
- Fix 8 missing reallocate_packet flags on packet-modifying helpers.
- Reject null pointer dereference with non-zero access size.
- Fix soundness bugs in 32-bit signed/unsigned comparison handling (#1038).
- Fix assertion crash in Assume when operands have different types (#1012).
- Fix widening termination by removing constraint re-addition in zone
  domain (#960).
- Propagate alloc_mem_size through helpers and decompose kfunc flags.

### Performance

- >4× faster verification on large programs through splitdbm graph
  internals modernization and zone domain optimizations (#1017).

### Diagnostics

- Add failure slicing: `--failure-slice` prints a minimal causal trace
  from the first verification error back to its root cause.
- Human-friendly CLI output: `PASS: section/function` / `FAIL: section/function`
  with first error and hint line, replacing the old CSV format.
- Add `-q`/`--quiet` flag (exit code only, no stdout).

### Infrastructure

- Overhaul ELF loader and bump ebpf-samples (#1026).
- Handle invalid BTF map metadata gracefully (#1034).
- Add MSVC debug assert handler (#1018).
- Simplify test framework: drop per-test diagnostic strings, reclassify
  genuinely-unsafe programs as rejections, document VerifyIssueKind enum
  centrally.
- Rename main executable from `bin/check` to `bin/prevail`.
- Remove dead code: `--domain` option (`linux`, `stats` paths),
  `linux_verifier`, `memsize` helpers, `collect_stats`, stale benchmark
  scripts.
- Move CLI entry point from `src/main/check.cpp` to `src/main.cpp`.
- Bump external/libbtf, external/bpf_conformance, actions/checkout.

## v0.1.3

Previous release. See git log for details.
