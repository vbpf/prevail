# ISA Instruction Forms

Instruction forms that are decoded but not semantically handled.

## Missing

- [ ] `CALL src=2` — helper call by BTF ID (kfunc). Decoded as `CallBtf`, immediately rejected.
- [x] `LDDW src=3` — variable address pseudo. Decoded as `LoadPseudo`, lowered to a 64-bit scalar immediate during CFG construction.
- [x] `LDDW src=4` — code address pseudo. Decoded as `LoadPseudo`, lowered to a 64-bit scalar immediate during CFG construction.
