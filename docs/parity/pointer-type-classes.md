# Pointer and Return Type Classes in Helper ABI

The helper prototype table covers helpers 0–211, but many signatures use argument or return
type classes that map to `UNSUPPORTED`. Until the type system can represent these pointer kinds,
the affected helpers are dead code.

Each item here is a type class that needs representation in the verifier's type system
and integration into helper argument/return checking.

## Return type classes

- [ ] `PTR_TO_SOCK_COMMON_OR_NULL` — returned by `sk_lookup_tcp`, `sk_lookup_udp`, `skc_lookup_tcp`
- [ ] `PTR_TO_SOCKET_OR_NULL` — returned by `sk_fullsock`
- [ ] `PTR_TO_TCP_SOCKET_OR_NULL` — returned by `tcp_sock`, `get_listener_sock`
- [ ] `PTR_TO_ALLOC_MEM_OR_NULL` — returned by `ringbuf_reserve`
- [ ] `PTR_TO_BTF_ID_OR_NULL` — returned by `sock_from_file`, `skc_to_*` helpers, `kptr_xchg`
- [ ] `PTR_TO_BTF_ID` (non-nullable) — returned by `get_current_task_btf`, `task_pt_regs`

## Argument type classes

- [ ] `PTR_TO_BTF_ID` — used by task/inode/cgroup/socket storage helpers, `copy_from_user_task`, `ima_file_hash`, `cgrp_storage_*`, `find_vma`
- [ ] `PTR_TO_SOCK_COMMON` — used by `sk_fullsock`, `tcp_sock`, `get_listener_sock`
- [ ] `PTR_TO_BTF_ID_SOCK_COMMON` — used by `sk_release`, `tcp_check_syncookie`, socket casting helpers
- [ ] `PTR_TO_SPIN_LOCK` — used by `spin_lock`, `spin_unlock`
- [ ] `PTR_TO_TIMER` — used by `timer_init`, `timer_set_callback`, `timer_start`, `timer_cancel`
- [ ] `PTR_TO_FUNC` — used by `for_each_map_elem`, `loop`, `find_vma`, `timer_set_callback`
- [ ] `PTR_TO_PERCPU_BTF_ID` — used by `per_cpu_ptr`, `this_cpu_ptr`
- [ ] `PTR_TO_ALLOC_MEM` — used by `ringbuf_submit`, `ringbuf_discard`
- [ ] `CONST_ALLOC_SIZE_OR_ZERO` — used by `ringbuf_reserve`
- [ ] `PTR_TO_CONST_STR` — used by `snprintf`, `strncmp`
- [ ] `PTR_TO_LONG` — used by `strtol`, `strtoul`, `kallsyms_lookup_name`
- [ ] `PTR_TO_INT` — used by `check_mtu`
