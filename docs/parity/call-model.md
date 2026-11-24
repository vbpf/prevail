# Call Model: Callbacks, Tail Calls, Global Functions

## Callback verification

- [x] **Helpers that take a callback are rejected** — the body of a callback is not analyzed, so a call to a helper or kfunc whose signature carries `PTR_TO_FUNC` is rejected when the program is prepared (`rejected: helper takes a callback, and callback bodies are not analyzed`), whatever the argument holds. This is conservative: accepting the call would run code that was never checked.
- [ ] **Callback target validity** — the check that the argument is a `func` whose `func_offset` is a single top-level instruction label with a reachable exit (`ValidCallbackTarget`) is kept, but not reached while such calls are rejected. It is necessary for accepting a callback and not sufficient.
- [x] **Function addresses from relocations** — an `lddw` relocated against code (clang's `&static_function`) loads a function pointer: `func` type, not null, not a number. Its target is left unknown (`func_offset` unconstrained). A function pointer's target label lives in `func_offset`, never in `uvalue`.
- [ ] **Callback body analysis** — the callback subprogram body is not verified under the contract its helper calls it with: argument types, return range, and the effect of zero or more runs on the caller's state. Tracked in [#797](https://github.com/vbpf/prevail/issues/797).
- [ ] **Callback frame semantics** — model the callback's stack frame and register state as a nested verification context.

## Tail calls

- [x] **Tail calls in subprograms** — no longer rejected unconditionally. A successful tail call replaces only the subprogram's frame, so each inlined tail-call site also has a successor that returns to the subprogram's caller with an unknown numeric `r0`, as if the subprogram had exited there. Like Linux, `bpf_tail_call` is treated as a packet-reallocating helper, since the target program may change packet data before that return.
- [x] **Stack left under a tail call** — the frames of the callers stay on the stack under the target program, once for each call of a chain, so as in Linux (`check_max_stack_depth_subprog()`) a tail call is refused where they hold 256 bytes or more. With the 33-call chain limit this bounds the stack of a chain. A `callx` is checked when its helper id is known.
- [ ] **Stack actually used by the callers** — Linux counts the bytes each caller's frame uses, rounded up to 32. Here every frame is `subprogram_stack_size` bytes whatever the function uses, so with the default 512-byte frames a tail call is accepted in the entry function only; `--stack-size` below 256 admits it in subprograms.
- [x] **Tail call chain depth tracking** — verifier enforces a tail-call chain limit of 33 during CFG validation.
- [x] **Failed tail call leaves `r0` unwritten** — `bpf_tail_call` is `RET_VOID` on Linux; after the call `r0` is unreadable (as in Linux), not a number.

## Global functions

- [ ] **Global function verification** — BPF global functions (non-static, `GLOBAL` linkage) are verified in Linux with a modular contract: the caller sees a summary, the callee is verified independently. Prevail inlines everything. For parity, global functions need contract-based verification with typed argument/return summaries.

## Interprocedural state

- [ ] **Callee-saved register correlation** — Linux tracks which registers are preserved across calls. Prevail's inlining approach handles this implicitly for local calls, but a contract-based model for global functions would need explicit callee-saved modeling.
