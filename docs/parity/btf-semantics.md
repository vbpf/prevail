# BTF-Driven Typing Beyond Mechanical Parsing

BTF section parsing and CO-RE relocations are implemented. What is missing is
*semantic use* of BTF information in verification.

## kfunc support

- [x] **kfunc prototype resolution** — resolve `CALL src=2` targets to typed prototypes via table lookup by BTF ID.
- [x] **kfunc prototype table** — maintain a table of known kfunc signatures (argument types, return types, flags).
- [x] **kfunc argument type checking** — verify arguments against resolved kfunc prototypes (table-driven subset).
- [x] **kfunc availability gating** — apply prototype-level availability checks (program type and privileged-only constraints) before analysis.
- [ ] **kfunc return type propagation** — propagate BTF-typed return values into the register state. Current subset supports integer and map-value-or-null style return contracts only.
- [ ] **kfunc flags** — per-flag handling for kfunc behavioral flags. Flags accepted today (type-level safety covered by existing checks):
  - `KF_ACQUIRE` — type propagation works; release obligation not enforced (same gap as ringbuf, tracked in [lifetime.md](lifetime.md))
  - `KF_DESTRUCTIVE` — privilege-level gate only
  - `KF_TRUSTED_ARGS` — arguments type-checked via normal assertion path
  - `KF_SLEEPABLE` — context constraint, not a memory-safety property

  Flags rejected (require unimplemented infrastructure):
  - `KF_RELEASE` — requires acquire/release state machine (see [lifetime.md](lifetime.md))

  Flags not yet in the `KfuncFlags` enum (Linux defines but Prevail does not):
  - `KF_RET_NULL` — forces null check on return value (safety-critical)
  - `KF_RCU` / `KF_RCU_PROTECTED` — RCU pointer trust and critical-section enforcement (safety-critical)
  - `KF_ITER_NEW` / `KF_ITER_NEXT` / `KF_ITER_DESTROY` — iterator lifecycle tracking (safety-critical)
  - `KF_DEPRECATED` — load-time warning (informational)
  - `KF_IMPLICIT_ARGS` — hidden argument injection (ABI)

## BTF-ID pointer typing

- [ ] **`PTR_TO_BTF_ID` type representation** — the type system needs to carry a BTF type ID alongside the pointer kind, so that helpers and kfuncs can check argument compatibility.
- [ ] **BTF-ID subtype compatibility** — Linux allows passing a derived type where a base type is expected (e.g., `struct tcp_sock*` where `struct sock*` is required). Requires BTF type graph traversal.

## BTF-guided map value layout

- [ ] **Structured map value fields** — use BTF to identify spin lock, timer, kptr, and other special fields within map value types, rather than requiring manual annotation.
- [ ] **Field offset validation** — verify that pointer arguments to `spin_lock`/`timer_init`/etc. actually point to correctly-typed fields within the map value at the right offset.
