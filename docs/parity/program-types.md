# Program Types and Context Descriptors

## Missing program types

Program types with no entry in the platform program-type table.

- [x] `BPF_PROG_TYPE_TRACING` — fentry/fexit/fmod_ret/iter attach types
- [x] `BPF_PROG_TYPE_LSM` — LSM hook programs
- [x] `BPF_PROG_TYPE_STRUCT_OPS` — struct_ops callback programs
- [x] `BPF_PROG_TYPE_EXT` — freplace / function replacement
- [x] `BPF_PROG_TYPE_SYSCALL` — privileged syscall introspection
- [x] `BPF_PROG_TYPE_NETFILTER` — netfilter hook programs (Linux 6.4+)
- [x] `BPF_PROG_TYPE_SK_LOOKUP` — socket lookup programs
- [x] `BPF_PROG_TYPE_SK_REUSEPORT` — SO_REUSEPORT selection programs
- [x] `BPF_PROG_TYPE_FLOW_DISSECTOR` — flow dissector programs
- [x] `BPF_PROG_TYPE_CGROUP_SYSCTL` — cgroup sysctl programs
- [x] `BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE` — writable raw tracepoint programs

## Context descriptor fidelity

Program types that exist but have approximate or incorrect context modeling.

- [x] Fix native type assignments — several program types are registered with `BPF_PROG_TYPE_SOCKET_FILTER` as native type instead of their actual kernel enum (e.g., `cgroup_sock_addr`, `sk_msg`, `lirc_mode2`).
- [x] `__sk_buff.data_meta` is a packet pointer for `sched_cls`/`sched_act` only — Linux rejects the field for `socket_filter`, `cgroup_skb`, `sk_skb`, `lwt_*` and `flow_dissector`, and the first three never compute it.
- [ ] `socket_filter` still models `__sk_buff.data`/`data_end` as packet pointers although Linux rejects both fields for it — kept because unrecognized section names fall back to this type.
- [ ] Context descriptor parity — field offsets and sizes match Linux 6.18 definitions for all registered program types.
- [x] Read-only contexts — program types whose `is_valid_access()` rejects every `BPF_WRITE` (kprobe, tracepoint, perf_event, tracing, LSM, struct_ops, XDP, ...) reject stores through the context pointer. Where only some attach points of a program type are read-only, the section prefix that names them is a row of its own: `cgroup/post_bind4` and `cgroup/post_bind6` are `cgroup_sock` programs (their context is the bound socket, a `struct bpf_sock`, not the `struct bpf_sock_addr` of `cgroup/bind4`), and unlike `cgroup/sock_create` they may store to none of its fields.
- [x] Read-only packets — `cgroup_skb`, `lwt_in`, `lwt_out`, `lwt_seg6local`, `sk_reuseport` and `flow_dissector` may read the packet but not write it (`may_access_direct_pkt_data()`): stores, atomics and helper output buffers into the packet are rejected (`EbpfProgramType::packet_read_only`).
- [x] Legacy packet access — `LD_ABS`/`LD_IND` are accepted only for `socket_filter`, `sched_cls` and `sched_act` (`may_access_skb()`), whose context is an sk_buff (`EbpfProgramType::legacy_packet_access`).
- [ ] Context field layouts — Linux does not run a context access as written: it rewrites it into an access to whatever backs the field at that offset, so an access is safe only if it is one that `is_valid_access()` admits for that field (its width, alignment and permission). `EbpfProgramType::ctx_layout` lists the fields of a context and the accesses each admits (`EbpfStructFieldDescriptor`: whole-width or narrow, read-only or writable, single or array), and a load or store through the context must be admitted by one of them. A program type without a layout keeps treating its context as plain memory of the descriptor's size. Layouts so far: `perf_event` (whole `pt_regs` words; `sample_period` and `addr` whole or narrowed). All other program types are still to be given one.
- [ ] Per-field context write permissions — for contexts with writable fields (`__sk_buff`, `bpf_sock_ops`, `bpf_sock_addr`, ...), stores are checked only against the data/data_end/data_meta slots, not against the per-program-type `BPF_WRITE` field set.
- [x] Return value ranges — a program type names the values it may return (`EbpfProgramType::return_range`), checked on `r0` at the top-level `exit`. The Linux table follows `return_retval_range()`: `[0, 1]` for `cgroup_device`, `cgroup_sock`, `cgroup_sockopt`, `cgroup_sysctl`, `sock_ops`, `sk_lookup` and `netfilter`; by attach point for `cgroup_skb` (`[0, 3]` on egress, else `[0, 1]`), `cgroup_sock_addr` (`[0, 3]` for bind, `[1, 1]` for recvmsg/getpeername/getsockname, else `[0, 1]`) and `tracing` (`[0, 0]` for fentry/fexit, `[0, 1]` for iter, any number for fmod_ret and tp_btf). The attach point is taken from the section name, so each range is a row of its own. Other program types may return any number, as in Linux.
- [ ] Return values that depend on a function prototype — an `lsm` hook returning an errno must return a value in `[-4095, 0]` and a boolean hook `[0, 1]`, and the previous program's result that such a program loads from its context is in the same range. A `struct_ops` member that returns a pointer must return null or an unmodified referenced object of that type. Both need the BTF prototype of the hook or member, which is not modeled, so `lsm` and `struct_ops` programs may return any number. The same holds for attach points the section table does not name (`kprobe.session`, `lsm_cgroup`).
- [ ] Model attach-type-dependent helper availability — Linux gates helper legality on (program type, attach type) pairs, not just program type alone.
- [ ] Helper ids that take a socket in some program types — Linux binds `bpf_get_socket_cookie`, `bpf_setsockopt` and `bpf_getsockopt` to a function that takes the context in some program types and to one that takes a `struct sock *` in others (`cgroup_sockopt`, `struct_ops`, `lsm`, `iter/tcp`, `sk_reuseport`, ...). The prototype rows describe the function that takes the context, and the helpers are offered only to the program types that bind the id to it (`context_variant_program_types` in `spec_prototypes.cpp`). The socket-taking functions are not modeled, so the other program types cannot call these helpers.
