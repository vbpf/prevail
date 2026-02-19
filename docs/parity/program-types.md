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
- [ ] Context descriptor parity — field offsets and sizes match Linux 6.18 definitions for all registered program types.
- [ ] Model attach-type-dependent helper availability — Linux gates helper legality on (program type, attach type) pairs, not just program type alone.
