# BTF-Driven Typing Beyond Mechanical Parsing

BTF section parsing and CO-RE relocations are implemented. What is missing is
*semantic use* of BTF information in verification.

## kfunc support

- [ ] **kfunc prototype resolution** — resolve `CALL src=2` targets to typed prototypes via BTF ID lookup.
- [ ] **kfunc prototype table** — maintain a table of known kfunc signatures (argument types, return types, flags).
- [ ] **kfunc argument type checking** — verify arguments against kfunc prototypes using BTF type information.
- [ ] **kfunc return type propagation** — propagate BTF-typed return values into the register state.
- [ ] **kfunc flags** — handle kfunc behavioral flags (e.g., `KF_ACQUIRE`, `KF_RELEASE`, `KF_TRUSTED_ARGS`, `KF_SLEEPABLE`, `KF_DESTRUCTIVE`).

## BTF-ID pointer typing

- [ ] **`PTR_TO_BTF_ID` type representation** — the type system needs to carry a BTF type ID alongside the pointer kind, so that helpers and kfuncs can check argument compatibility.
- [ ] **BTF-ID subtype compatibility** — Linux allows passing a derived type where a base type is expected (e.g., `struct tcp_sock*` where `struct sock*` is required). Requires BTF type graph traversal.

## BTF-guided map value layout

- [ ] **Structured map value fields** — use BTF to identify spin lock, timer, kptr, and other special fields within map value types, rather than requiring manual annotation.
- [ ] **Field offset validation** — verify that pointer arguments to `spin_lock`/`timer_init`/etc. actually point to correctly-typed fields within the map value at the right offset.
