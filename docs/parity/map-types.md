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
- [x] **Inner map of a legacy map definition** — a `maps` record carries no tag for its layout, so the layout is taken from the record size, as loaders do: 24 and 28 bytes are the kernel samples' `bpf_load_map_def`, where `inner_map_idx` is the position of the inner map; 32 and 36 bytes are iproute2's `struct bpf_elf_map`, where `inner_id` names the first map with that `id`; shorter records (libbpf's `struct bpf_map_def`) and longer ones name no inner map. Only a map of maps names one. A lookup in a map of maps with no named inner map yields a pointer about which nothing is known, so it cannot be used as a map.
- [ ] **External map FD reasoning** — when map metadata is unavailable (externally provided FDs), the verifier cannot reason about map properties. Needs a model for unknown-but-constrained map descriptors. An `lddw` that an ELF object stores already marked as a map load (`src` 1, 2, 5 or 6), instead of leaving it to a relocation, holds such an FD or an `fd_array` index; the ELF reader refuses the program that contains one, and the callers of that program.
- [x] **Program-side access flags** — the map behind `.rodata`/`.rodata.*` and maps declared with `BPF_F_RDONLY_PROG` are read-only for the program, and maps declared with `BPF_F_WRONLY_PROG` (legacy `maps` records and BTF-defined maps) are write-only: stores, atomics and helper output buffers into a read-only map value, and loads, atomics (fetching or not) and helper input buffers from a write-only one, are rejected, as are `map_update_elem`, `map_delete_elem`, `map_push_elem` and `map_pop_elem` on a read-only map. The access travels with the pointer as `shared_access`; a pointer that may point into maps of different access may do only what all of them allow.
- [x] **Tail-call map constraints in subprograms** — tail calls in subprograms are accepted where the callers' frames are small enough (see [call-model.md](call-model.md)); `map_fd_programs` argument typing remains enforced for `bpf_tail_call`.
- [ ] **Map-type-dependent `map_lookup_elem` results** — Linux returns a socket for `SOCKMAP`/`SOCKHASH`/`XSKMAP` and a read-only value for `DEVMAP`/`DEVMAP_HASH`, and takes a socket as the `map_update_elem` value for `SOCKMAP`/`SOCKHASH`. Only plain map values and inner maps are modeled, so `map_lookup_elem`/`map_update_elem`/`map_delete_elem` reject these map types (`allowed_map_types`).
- [x] **Map types in sleepable programs** — as Linux's `check_map_prog_compatibility()` does, a sleepable program (`*.s/` sections and `syscall/`) may use only array, hash, ring-buffer, local-storage, queue, stack, map-of-maps and arena maps (`EbpfMapType::usable_in_sleepable`); a load of any other map's fd or value address is rejected.
- [x] **One cgroup storage map per type** — `bpf_get_local_storage` returns the program's storage buffer of the type of the map it is passed, so its result can be sized by that map only if the program has a single map of the type. As in Linux, a program that references two `CGROUP_STORAGE` maps, or two `PERCPU_CGROUP_STORAGE` maps, is rejected, and so is a referenced map of maps whose inner map has one of these types.
- [ ] **Arena map semantics** — `BPF_MAP_TYPE_ARENA` is in the map-type table, but arena-specific verification (user-mappable memory, `addr_space_cast` instruction) is not implemented.
