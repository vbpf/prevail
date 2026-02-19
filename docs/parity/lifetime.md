# Object Lifetime and Ownership Tracking

The Linux verifier tracks owned references that must be released before program exit.
Prevail has no reference tracking. This blocks multiple helper families.

## Reference tracking infrastructure

- [ ] **Acquire/release state machine** — track which registers hold owned references, enforce release on all exit paths, reject double-release and use-after-release.
- [ ] **Reference type tags** — distinguish reference kinds (socket ref, alloc-mem ref, kptr ref) so release helpers can be type-checked against acquisition source.

## Specific ownership protocols

- [ ] **Socket references** — `sk_lookup_tcp`/`sk_lookup_udp`/`skc_lookup_tcp` acquire; `sk_release` releases. All paths must release before exit.
- [ ] **Ringbuf reserve/submit/discard** — `ringbuf_reserve` acquires an alloc-mem reference; exactly one of `ringbuf_submit` or `ringbuf_discard` must consume it.
- [ ] **kptr exchange** — `kptr_xchg` swaps a BTF-ID pointer into a map value and returns the old one. The returned pointer is an owned reference if non-null.
- [ ] **Dynptr lifecycle** — `dynptr_from_mem` and ringbuf dynptr helpers establish dynptr ownership; associated resources must be released.

## Map-value embedded object ownership

- [ ] **Spin lock regions** — `spin_lock` starts a critical section; `spin_unlock` ends it. No other lock may be held, no blocking helpers may be called, and the lock must be released on all exit paths.
- [ ] **Timer field ownership** — `timer_init` associates a timer with a map value; `timer_set_callback` transfers a callback reference; timer resources have map-lifetime ownership semantics.
