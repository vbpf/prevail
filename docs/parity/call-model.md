# Call Model: Callbacks, Tail Calls, Global Functions

## Callback verification

- [ ] **`PTR_TO_FUNC` argument type** — represent function pointer arguments in the type system.
- [ ] **Callback body analysis** — verify the callback subprogram body against the callback contract (expected argument types, return type, side-effect constraints).
- [ ] **Callback frame semantics** — model the callback's stack frame and register state as a nested verification context.

## Tail calls

- [ ] **Tail calls in subprograms** — currently rejected unconditionally (`"tail call not supported in subprogram"`). Linux allows tail calls from subprograms under specific conditions.
- [ ] **Tail call chain depth tracking** — Linux limits total tail call depth to 33. No chain-depth tracking exists.

## Global functions

- [ ] **Global function verification** — BPF global functions (non-static, `GLOBAL` linkage) are verified in Linux with a modular contract: the caller sees a summary, the callee is verified independently. Prevail inlines everything. For parity, global functions need contract-based verification with typed argument/return summaries.

## Interprocedural state

- [ ] **Callee-saved register correlation** — Linux tracks which registers are preserved across calls. Prevail's inlining approach handles this implicitly for local calls, but a contract-based model for global functions would need explicit callee-saved modeling.
