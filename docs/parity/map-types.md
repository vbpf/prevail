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
- [x] **Tail-call map constraints in subprograms** — tail calls in subprograms are accepted; `map_fd_programs` argument typing remains enforced for `bpf_tail_call`.
