# Changelog

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
