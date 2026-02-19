# ISA Instruction Forms

Instruction forms that are decoded but not semantically handled.

## Missing

- [ ] `CALL src=2` — helper call by BTF ID (kfunc). Decoded as `CallBtf`, immediately rejected.
- [ ] `LDDW src=3` — variable address pseudo. Decoded as `LoadPseudo`, immediately rejected.
- [ ] `LDDW src=4` — code address pseudo. Decoded as `LoadPseudo`, immediately rejected.
