# Map Types and Map Semantics

## Missing map types

Map types with no entry in the platform map-type table.

- [ ] `BPF_MAP_TYPE_RINGBUF`
- [ ] `BPF_MAP_TYPE_USER_RINGBUF`
- [ ] `BPF_MAP_TYPE_ARENA` (Linux 6.9+)
- [ ] `BPF_MAP_TYPE_BLOOM_FILTER`
- [ ] `BPF_MAP_TYPE_SK_STORAGE`
- [ ] `BPF_MAP_TYPE_INODE_STORAGE`
- [ ] `BPF_MAP_TYPE_TASK_STORAGE`
- [ ] `BPF_MAP_TYPE_CGRP_STORAGE`
- [ ] `BPF_MAP_TYPE_STRUCT_OPS`

## Conditionally compiled map types

These map types are only available when compiled on a Linux host with the relevant kernel headers.
They should be unconditionally available.

- [ ] `BPF_MAP_TYPE_XSKMAP`
- [ ] `BPF_MAP_TYPE_SOCKHASH`
- [ ] `BPF_MAP_TYPE_CGROUP_STORAGE`
- [ ] `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY`
- [ ] `BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE`
- [ ] `BPF_MAP_TYPE_QUEUE`
- [ ] `BPF_MAP_TYPE_STACK`

## Map semantic gaps

- [ ] **Map-in-map identity propagation** — after `map_lookup_elem` on an outer map, the inner map descriptor (type, key/value size) should be available for subsequent helper calls. Currently, inner map identity is lost across control flow.
- [ ] **External map FD reasoning** — when map metadata is unavailable (externally provided FDs), the verifier cannot reason about map properties. Needs a model for unknown-but-constrained map descriptors.
- [ ] **Tail-call map constraints in subprograms** — tail calls inside subprograms are rejected unconditionally. Linux allows them under specific conditions.
