# Object Lifetime and Ownership Tracking

The Linux verifier tracks owned references that must be released before program exit.
Prevail has no reference lifecycle tracking. The type system *can represent* pointer kinds
involved in ownership (e.g., `T_ALLOC_MEM`, `T_SOCKET`, `T_BTF_ID`), and type-level safety
is in parity: pointer types are correctly propagated, bounds-checked, and prevented from
leaking to externally-visible memory. What is missing is the lifecycle enforcement layer:
acquire/release obligations are not tracked, so programs that leak resources or use them
after release are accepted.

This is an intentional phasing decision. Memory safety and data-leakage prevention are
enforced at the type level today. Resource lifecycle tracking is the next layer, to be
implemented behind a feature flag.

## Reference tracking infrastructure

- [ ] **Acquire/release state machine** — track which registers hold owned references, enforce release on all exit paths, reject double-release and use-after-release.
- [ ] **Reference type tags** — distinguish reference kinds (socket ref, alloc-mem ref, kptr ref) so release helpers can be type-checked against acquisition source.

## Specific ownership protocols

- [ ] **Socket references** — `sk_lookup_tcp`/`sk_lookup_udp`/`skc_lookup_tcp` acquire; `sk_release` releases. All paths must release before exit. Type propagation to `T_SOCKET` works today; lifecycle enforcement does not.
- [ ] **Ringbuf reserve/submit/discard** — `ringbuf_reserve` acquires an alloc-mem reference; exactly one of `ringbuf_submit` or `ringbuf_discard` must consume it. Type checking and bounds checking work today (`T_ALLOC_MEM` propagation, allocation size tracking, argument enforcement); ownership tracking does not.
- [ ] **kfunc acquire/release** — kfuncs with `KF_ACQUIRE` are accepted (type propagation works); `KF_RELEASE` kfuncs are rejected (require the state machine). Once the state machine exists, both sides can be wired in.
- [ ] **kptr exchange** — `kptr_xchg` swaps a BTF-ID pointer into a map value and returns the old one. The returned pointer is an owned reference if non-null.
- [ ] **Dynptr lifecycle** — `dynptr_from_mem` and ringbuf dynptr helpers establish dynptr ownership; associated resources must be released. Requires dynptr type representation first.

## Map-value embedded object ownership

- [ ] **Spin lock regions** — `spin_lock` starts a critical section; `spin_unlock` ends it. No other lock may be held, no blocking helpers may be called, and the lock must be released on all exit paths.
- [ ] **Timer field ownership** — `timer_init` associates a timer with a map value; `timer_set_callback` transfers a callback reference; timer resources have map-lifetime ownership semantics.
