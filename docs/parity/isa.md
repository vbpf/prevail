# ISA Instruction Forms

## Completed

All instruction forms from the base BPF ISA (RFC 9669) are decoded and semantically handled:

- [x] `CALL src=2` — helper call by BTF ID (kfunc). Decoded as `CallBtf`, resolved via table to typed call contracts; unknown/unsupported BTF IDs are rejected.
- [x] `LDDW src=3` — variable address pseudo. Decoded as `LoadPseudo`, lowered to a 64-bit scalar immediate during CFG construction.
- [x] `LDDW src=4` — code address pseudo. Decoded as `LoadPseudo` and propagated as `func` type for callback helper arguments.

## Missing post-RFC extensions

- [ ] **`may_goto`** (Linux 6.9+) — open-coded iterator loop bound instruction. Not decoded; programs using it are rejected at load time.
- [ ] **`addr_space_cast`** (Linux 6.9+) — address space cast for arena pointers. Not decoded; required for `BPF_MAP_TYPE_ARENA` semantics beyond map-type recognition.
