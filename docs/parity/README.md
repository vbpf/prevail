# eBPF Language Parity Tracking

## Purpose

Track concrete, verifiable feature gaps between Prevail and the Linux eBPF verifier (baseline: Linux 6.18).
Each item is a binary checkbox: implemented or not. PRs that close a gap should check the relevant box.

This is **not** an implementation plan. It records *what* is missing, not *how* to build it.

## Scope

"Parity" means: a program accepted by the Linux verifier for a given program type should generally
be accepted (or rejected for the same semantic reason). Helper and type rules should be compatible
enough that common Linux eBPF codebases do not need structural rewrites.

Out of scope:
- In-kernel deployment mechanics
- Runtime performance
- Privilege model policy (unless it changes language acceptance)

## Non-Goals

- **Complete precision parity with the Linux verifier.** The Linux verifier uses path enumeration,
  aggressive loop unrolling, and heuristic-driven state pruning. Prevail uses abstract interpretation
  with widening. These are fundamentally different analysis strategies with different precision
  profiles. The goal is *robust precision* — not matching Linux's accept/reject decision on every
  possible program.

- **Loop unrolling.** The Linux verifier unrolls loops up to a bounded iteration count to achieve
  path-level precision. Prevail uses abstract interpretation with widening as the primary loop
  analysis strategy. Loop unrolling is not planned. Where Linux relies on unrolling to prove bounds,
  Prevail must derive the same facts through invariant computation.

## Tracking Files

| File | Category |
|---|---|
| [isa.md](isa.md) | ISA instruction forms |
| [pointer-type-classes.md](pointer-type-classes.md) | Pointer and return type classes in helper ABI |
| [helper-families.md](helper-families.md) | Helper function families |
| [program-types.md](program-types.md) | Program types and context descriptors |
| [map-types.md](map-types.md) | Map types and map semantics |
| [call-model.md](call-model.md) | Call model: callbacks, tail calls, global functions |
| [lifetime.md](lifetime.md) | Object lifetime and ownership tracking |
| [btf-semantics.md](btf-semantics.md) | BTF-driven typing beyond mechanical parsing |

## Dependency Structure

Many gaps are coupled. The most important dependency chains:

1. **Pointer type classes** → helper families, lifetime tracking, kfuncs
2. **BTF semantic integration** → kfuncs, BTF-ID pointer typing, object-type reasoning
3. **Lifetime tracking** → socket helpers, ringbuf reserve/submit, kptr exchange
4. **Callback verification** → `bpf_loop`, `for_each_map_elem`, timer callbacks
5. **Program-type/context fidelity** → correct helper availability per attach point
6. **Map identity propagation** → map-in-map chains, inner map descriptor reasoning
