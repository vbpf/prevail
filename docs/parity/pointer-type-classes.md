# Pointer and Return Type Classes in Helper ABI

The helper prototype table covers helpers 0–211, but some signatures use argument or return
type classes that are not yet modeled in verifier call semantics. Until the type system can represent
these pointer kinds and propagate them through checks/transformers, the affected helpers remain unavailable.

Each item here is a type class that needs representation in the verifier's type system
and integration into helper argument/return checking.

## Return type classes

### Implemented

Return types that are classified and propagated into register state:

- [x] `EBPF_RETURN_TYPE_INTEGER` / `INTEGER_OR_NO_RETURN_IF_SUCCEED` — scalar return
- [x] `PTR_TO_MAP_VALUE_OR_NULL` — returned by map lookup helpers; propagated as nullable map-value pointer
- [x] `PTR_TO_SOCK_COMMON_OR_NULL` / `PTR_TO_SOCKET_OR_NULL` / `PTR_TO_TCP_SOCKET_OR_NULL` — all mapped to `T_SOCKET` (nullable). Type-system representation works; lifecycle tracking does not (see [lifetime.md](lifetime.md)).
- [x] `PTR_TO_ALLOC_MEM_OR_NULL` — mapped to `T_ALLOC_MEM` (nullable). Type propagation works; ownership tracking does not (see [lifetime.md](lifetime.md)).
- [x] `PTR_TO_BTF_ID_OR_NULL` / `PTR_TO_MEM_OR_BTF_ID_OR_NULL` — mapped to `T_BTF_ID` (nullable)
- [x] `PTR_TO_BTF_ID` / `PTR_TO_MEM_OR_BTF_ID` (non-nullable) — mapped to `T_BTF_ID`

### Not implemented

- [ ] `EBPF_RETURN_TYPE_UNSUPPORTED` — catch-all for return types with no verifier model. Helpers using this are rejected.

## Argument type classes

### Implemented

- [x] `PTR_TO_MAP_VALUE` / `PTR_TO_MAP_VALUE_OR_NULL` — map value pointers with offset/size tracking
- [x] `PTR_TO_CTX` — program context pointer
- [x] `PTR_TO_STACK` / `PTR_TO_STACK_OR_NULL` — stack pointers with bounds checking
- [x] `PTR_TO_FUNC` — callback function pointer; validated as singleton code address targeting a label with reachable exit
- [x] `PTR_TO_ALLOC_MEM` — used by `ringbuf_submit`, `ringbuf_discard`; enforces `T_ALLOC_MEM` type
- [x] `CONST_ALLOC_SIZE_OR_ZERO` — used by `ringbuf_reserve`; enforces numeric type
- [x] `PTR_TO_LONG` — used by `strtol`, `strtoul`; verified as writable 8-byte stack pointer
- [x] `PTR_TO_INT` — used by `check_mtu`; verified as writable 4-byte stack pointer
- [x] `PTR_TO_SOCKET` — enforces `T_SOCKET` type
- [x] `PTR_TO_BTF_ID` — enforces `T_BTF_ID` type (argument-side check only; no BTF type-ID compatibility checking)

### Not implemented

- [ ] `PTR_TO_SOCK_COMMON` — used by `sk_fullsock`, `tcp_sock`, `get_listener_sock`. Currently accepted as generic socket but lacks the socket-subtype distinction.
- [ ] `PTR_TO_BTF_ID_SOCK_COMMON` — used by `sk_release`, `tcp_check_syncookie`, socket casting helpers. Requires BTF-ID-level socket type discrimination.
- [ ] `PTR_TO_SPIN_LOCK` — used by `spin_lock`, `spin_unlock`. Requires map-value field offset validation via BTF.
- [ ] `PTR_TO_TIMER` — used by `timer_init`, `timer_set_callback`, `timer_start`, `timer_cancel`. Requires map-value field offset validation via BTF.
- [ ] `PTR_TO_PERCPU_BTF_ID` — used by `per_cpu_ptr`, `this_cpu_ptr`. Requires per-CPU pointer semantics.
- [ ] `PTR_TO_CONST_STR` — used by `snprintf`, `strncmp`. Requires proof that pointer targets a null-terminated string in a read-only map value at a constant offset.
