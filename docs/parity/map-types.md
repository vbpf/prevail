# Map Types and Map Semantics

## Missing map types

Map types with no entry in the platform map-type table.

- [x] `BPF_MAP_TYPE_RINGBUF`
- [x] `BPF_MAP_TYPE_USER_RINGBUF`
- [x] `BPF_MAP_TYPE_ARENA` (Linux 6.9+)
- [x] `BPF_MAP_TYPE_BLOOM_FILTER`
- [x] `BPF_MAP_TYPE_SK_STORAGE`
- [x] `BPF_MAP_TYPE_INODE_STORAGE`
- [x] `BPF_MAP_TYPE_TASK_STORAGE`
- [x] `BPF_MAP_TYPE_CGRP_STORAGE`
- [x] `BPF_MAP_TYPE_STRUCT_OPS`

## Conditionally compiled map types

These map types are only available when compiled on a Linux host with the relevant kernel headers.
They should be unconditionally available.

- [x] `BPF_MAP_TYPE_XSKMAP`
- [x] `BPF_MAP_TYPE_SOCKHASH`
- [x] `BPF_MAP_TYPE_CGROUP_STORAGE`
- [x] `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY`
- [x] `BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE`
- [x] `BPF_MAP_TYPE_QUEUE`
- [x] `BPF_MAP_TYPE_STACK`

## Map semantic gaps

- [ ] **Map-in-map identity propagation** — after `map_lookup_elem` on an outer map, the inner map descriptor (type, key/value size) should be available for subsequent helper calls. Currently, inner map identity is lost across control flow.
- [ ] **External map FD reasoning** — when map metadata is unavailable (externally provided FDs), the verifier cannot reason about map properties. Needs a model for unknown-but-constrained map descriptors.
- [x] **Program-side access flags** — the map behind `.rodata`/`.rodata.*` and maps declared with `BPF_F_RDONLY_PROG` are read-only for the program, and maps declared with `BPF_F_WRONLY_PROG` (legacy `maps` records and BTF-defined maps) are write-only: stores, atomics and helper output buffers into a read-only map value, and loads, atomics (fetching or not) and helper input buffers from a write-only one, are rejected, as are `map_update_elem`, `map_delete_elem`, `map_push_elem` and `map_pop_elem` on a read-only map. The access travels with the pointer as `shared_access`; a pointer that may point into maps of different access may do only what all of them allow.
- [x] **Tail-call map constraints in subprograms** — tail calls in subprograms are accepted; `map_fd_programs` argument typing remains enforced for `bpf_tail_call`.
- [ ] **Map-type-dependent `map_lookup_elem` results** — Linux returns a socket for `SOCKMAP`/`SOCKHASH`/`XSKMAP` and a read-only value for `DEVMAP`/`DEVMAP_HASH`, and takes a socket as the `map_update_elem` value for `SOCKMAP`/`SOCKHASH`. Only plain map values and inner maps are modeled, so `map_lookup_elem`/`map_update_elem`/`map_delete_elem` reject these map types (`allowed_map_types`).
- [x] **Map types in sleepable programs** — as Linux's `check_map_prog_compatibility()` does, a sleepable program (`*.s/` sections and `syscall/`) may use only array, hash, ring-buffer, local-storage, queue, stack, map-of-maps and arena maps (`EbpfMapType::usable_in_sleepable`); a load of any other map's fd or value address is rejected.
- [ ] **Arena map semantics** — `BPF_MAP_TYPE_ARENA` is in the map-type table, but arena-specific verification (user-mappable memory, `addr_space_cast` instruction) is not implemented.
