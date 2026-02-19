# Call Model: Callbacks, Tail Calls, Global Functions

## Callback verification

- [x] **`PTR_TO_FUNC` argument type** — helper signatures now carry `PTR_TO_FUNC`, and verifier checks enforce `func`-typed callback registers.
- [x] **Callback target validity** — helper calls with `PTR_TO_FUNC` now require singleton code-address targets that resolve to valid top-level instruction labels.
- [ ] **Callback body analysis** — verify the callback subprogram body against the callback contract (expected argument types, return type, side-effect constraints). Basic shape validation is present: callback targets must have a reachable exit.
- [ ] **Callback frame semantics** — model the callback's stack frame and register state as a nested verification context.

## Tail calls

- [x] **Tail calls in subprograms** — no longer rejected unconditionally.
- [x] **Tail call chain depth tracking** — verifier enforces a tail-call chain limit of 33 during CFG validation.

## Global functions

- [ ] **Global function verification** — BPF global functions (non-static, `GLOBAL` linkage) are verified in Linux with a modular contract: the caller sees a summary, the callee is verified independently. Prevail inlines everything. For parity, global functions need contract-based verification with typed argument/return summaries.

## Interprocedural state

- [ ] **Callee-saved register correlation** — Linux tracks which registers are preserved across calls. Prevail's inlining approach handles this implicitly for local calls, but a contract-based model for global functions would need explicit callee-saved modeling.
