# Helper Function Families

Groups of helpers that are blocked by shared missing capabilities.
Items here represent *families*, not individual helper IDs. A family is checked off
when all its members are semantically functional.

## Blocked by pointer type classes

- [ ] **Socket lookup family** — `sk_lookup_tcp` (84), `sk_lookup_udp` (85), `skc_lookup_tcp` (99), `sk_fullsock` (95), `tcp_sock` (96), `get_listener_sock` (98). Requires socket pointer return/argument types + reference tracking.
- [ ] **Socket casting family** — `skc_to_tcp6_sock` (136), `skc_to_tcp_sock` (137), `skc_to_tcp_timewait_sock` (138), `skc_to_tcp_request_sock` (139), `skc_to_udp6_sock` (140), `sock_from_file` (162), `skc_to_mptcp_sock` (196). Requires `PTR_TO_BTF_ID` return types.
- [ ] **BTF object helpers** — `get_current_task_btf` (158), `task_pt_regs` (175), `per_cpu_ptr` (153), `this_cpu_ptr` (154). Requires `PTR_TO_BTF_ID` and `PTR_TO_PERCPU_BTF_ID`.
- [ ] **Storage helpers** — task/inode/cgroup/sk storage `get`/`delete` families. Requires `PTR_TO_BTF_ID` argument class.

## Blocked by callback verification

- [ ] **`bpf_loop`** (181) — requires `PTR_TO_FUNC` + callback body analysis.
- [ ] **`bpf_for_each_map_elem`** (164) — requires `PTR_TO_FUNC` + callback body analysis.
- [ ] **`bpf_find_vma`** (180) — requires `PTR_TO_FUNC` + `PTR_TO_BTF_ID` + callback body analysis.

## Blocked by lifetime/ownership tracking

- [ ] **Ringbuf reserve/submit/discard** — `ringbuf_reserve` (131), `ringbuf_submit` (132), `ringbuf_discard` (133). Requires `PTR_TO_ALLOC_MEM` types + ownership tracking.
- [ ] **kptr exchange** — `kptr_xchg` (194). Requires `PTR_TO_BTF_ID` + ownership transfer semantics.
- [ ] **Socket release** — `sk_release` (86). Requires `PTR_TO_BTF_ID_SOCK_COMMON` + reference release tracking.

## Blocked by map-value embedded object types

- [ ] **Spin lock** — `spin_lock` (93), `spin_unlock` (94). Requires `PTR_TO_SPIN_LOCK` + lock-region tracking.
- [ ] **Timer** — `timer_init` (169), `timer_set_callback` (170), `timer_start` (171), `timer_cancel` (172). Requires `PTR_TO_TIMER` + `PTR_TO_FUNC`.

## Dynptr family

- [ ] **Dynptr core** — `dynptr_from_mem` (197), `dynptr_read` (201), `dynptr_write` (202), `dynptr_data` (203). Requires dynptr type representation + slice semantics.
- [ ] **Dynptr ringbuf** — `ringbuf_reserve_dynptr` (198), `ringbuf_submit_dynptr` (199), `ringbuf_discard_dynptr` (200). Requires dynptr + ownership tracking.
- [ ] **User ringbuf** — `user_ringbuf_drain` (209). Requires callback + dynptr support.

## String/scalar output helpers

- [ ] **String helpers** — `snprintf` (165), `strncmp` (182). Requires `PTR_TO_CONST_STR`.
- [ ] **Scalar parse helpers** — `strtol` (105), `strtoul` (106). Requires `PTR_TO_LONG`.
- [ ] **MTU check** — `check_mtu` (163). Requires `PTR_TO_INT`.

## Helpers beyond table range

- [ ] **Helpers beyond 0-211 in Linux 6.18** — all helper IDs present in Linux 6.18 beyond 211 have prototype coverage in the verifier tables.
