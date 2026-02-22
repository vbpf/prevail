# Helper Function Families

Groups of helpers organized by their blocking dependencies.
Items here represent *families*, not individual helper IDs. A family is checked off
when all its members are semantically functional (type-checked, ownership-tracked where required).

## Fully functional

- [x] **Scalar parse helpers** — `strtol` (105), `strtoul` (106). `PTR_TO_LONG` verified as writable 8-byte stack pointer.
- [x] **MTU check** — `check_mtu` (163). `PTR_TO_INT` verified as writable 4-byte stack pointer.
- [x] **Helpers beyond 0–211 in Linux 6.18** — all helper IDs present in Linux 6.18 beyond 211 have prototype coverage in the verifier tables.

## Memory-safe but missing ownership tracking

These helpers are type-checked and bounds-checked. The remaining gap is resource lifecycle
enforcement, tracked in [lifetime.md](lifetime.md).

- [ ] **Ringbuf reserve/submit/discard** — `ringbuf_reserve` (131), `ringbuf_submit` (132), `ringbuf_discard` (133). Type propagation works: `ringbuf_reserve` returns `T_ALLOC_MEM` (nullable) with offset=0 and size from the allocation size argument. Access through the returned pointer is bounds-checked. `ringbuf_submit`/`ringbuf_discard` enforce `T_ALLOC_MEM` argument type. **Missing**: ownership tracking — the verifier does not enforce that exactly one of submit/discard is called on every path, so programs that leak a reservation or use-after-free are accepted.

## Blocked by pointer type classes

- [ ] **Socket lookup family** — `sk_lookup_tcp` (84), `sk_lookup_udp` (85), `skc_lookup_tcp` (99), `sk_fullsock` (95), `tcp_sock` (96), `get_listener_sock` (98). Type propagation to `T_SOCKET` works; blocked on `PTR_TO_SOCK_COMMON` argument subtyping + reference tracking.
- [ ] **Socket casting family** — `skc_to_tcp6_sock` (136), `skc_to_tcp_sock` (137), `skc_to_tcp_timewait_sock` (138), `skc_to_tcp_request_sock` (139), `skc_to_udp6_sock` (140), `sock_from_file` (162), `skc_to_mptcp_sock` (196). Requires BTF-ID-level socket subtype discrimination in return types.
- [ ] **BTF object helpers** — `get_current_task_btf` (158), `task_pt_regs` (175), `per_cpu_ptr` (153), `this_cpu_ptr` (154). Requires `PTR_TO_BTF_ID` subtype compatibility and `PTR_TO_PERCPU_BTF_ID`.
- [ ] **Storage helpers** — task/inode/cgroup/sk storage `get`/`delete` families. Requires `PTR_TO_BTF_ID` argument class.
- [ ] **String helpers** — `snprintf` (165), `strncmp` (182). Requires `PTR_TO_CONST_STR`: proof that pointer targets a null-terminated string in a read-only map value at a constant offset.

## Blocked by callback body analysis

- [ ] **`bpf_loop`** (181) — `PTR_TO_FUNC` argument type is checked (singleton code address, reachable exit), but the callback body is not verified against its contract (expected argument types, return type, side-effect constraints).
- [ ] **`bpf_for_each_map_elem`** (164) — same: target validation only, no body analysis.
- [ ] **`bpf_find_vma`** (180) — same, plus requires `PTR_TO_BTF_ID` for the VMA argument.

## Blocked by lifetime/ownership tracking

- [ ] **kptr exchange** — `kptr_xchg` (194). Requires `PTR_TO_BTF_ID` + ownership transfer semantics.
- [ ] **Socket release** — `sk_release` (86). Requires `PTR_TO_BTF_ID_SOCK_COMMON` + reference release tracking.

## Blocked by map-value embedded object types

- [ ] **Spin lock** — `spin_lock` (93), `spin_unlock` (94). Requires `PTR_TO_SPIN_LOCK` (BTF field offset validation) + lock-region tracking.
- [ ] **Timer** — `timer_init` (169), `timer_set_callback` (170), `timer_start` (171), `timer_cancel` (172). Requires `PTR_TO_TIMER` (BTF field offset validation) + `PTR_TO_FUNC` callback body analysis.

## Blocked by dynptr type representation

- [ ] **Dynptr core** — `dynptr_from_mem` (197), `dynptr_read` (201), `dynptr_write` (202), `dynptr_data` (203). Requires dynptr stack-slot tracking with typestate (initialized/uninitialized) and slice semantics.
- [ ] **Dynptr ringbuf** — `ringbuf_reserve_dynptr` (198), `ringbuf_submit_dynptr` (199), `ringbuf_discard_dynptr` (200). Requires dynptr + mandatory release tracking.
- [ ] **User ringbuf** — `user_ringbuf_drain` (209). Requires callback body analysis + dynptr support (callback receives `PTR_TO_DYNPTR`).

## Blocked by BPF exception support

- [ ] **`bpf_throw`** — kfunc for BPF exceptions (Linux 6.7+). Requires exception frame modeling. Not defined in the kfunc table.
