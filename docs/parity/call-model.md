# Call Model: Callbacks, Tail Calls, Global Functions

## Callback verification

- [x] **`PTR_TO_FUNC` argument type** — helper signatures carry `PTR_TO_FUNC`; verifier enforces `T_FUNC` type on the register.
- [x] **Callback target validity** — helper calls with `PTR_TO_FUNC` require a singleton code-address register that resolves to a valid top-level instruction label (not a jump target, not Entry/Exit) with a reachable exit.
- [ ] **Callback body analysis** — the callback subprogram body is not verified. Only structural checks are performed (valid label, reachable exit). No checking of callback argument types, return type, or side-effect constraints. The callback's code is present in the CFG but not analyzed under a callback-specific contract.
- [ ] **Callback frame semantics** — model the callback's stack frame and register state as a nested verification context.

## Tail calls

- [x] **Tail calls in subprograms** — no longer rejected unconditionally. A successful tail call replaces only the subprogram's frame, so each inlined tail-call site also has a successor that returns to the subprogram's caller with an unknown numeric `r0`, as if the subprogram had exited there. Like Linux, `bpf_tail_call` is treated as a packet-reallocating helper, since the target program may change packet data before that return.
- [x] **Tail call chain depth tracking** — verifier enforces a tail-call chain limit of 33 during CFG validation.
- [x] **Failed tail call leaves `r0` unwritten** — `bpf_tail_call` is `RET_VOID` on Linux; after the call `r0` is unreadable (as in Linux), not a number.

## Global functions

- [ ] **Global function verification** — BPF global functions (non-static, `GLOBAL` linkage) are verified in Linux with a modular contract: the caller sees a summary, the callee is verified independently. Prevail inlines everything. For parity, global functions need contract-based verification with typed argument/return summaries.

## Interprocedural state

- [ ] **Callee-saved register correlation** — Linux tracks which registers are preserved across calls. Prevail's inlining approach handles this implicitly for local calls, but a contract-based model for global functions would need explicit callee-saved modeling.
