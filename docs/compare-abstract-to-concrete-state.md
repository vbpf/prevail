# Observation–Invariant Consistency Checking

Related issue: [`#728`](https://github.com/vbpf/prevail/issues/728)

## Summary

Prevail provides a test-oriented API that checks whether a *runtime observation* (expressed as a set of string constraints) is compatible with Prevail’s computed abstract invariant at a given program point.

This is an abstract-interpretation-focused feature: it acts as a **semantic cross-check** that helps validate transfer functions, invariant construction, and modeling assumptions by comparing them against observed (often partial) executions.

Typical use cases include YAML-driven regression tests and VM/JIT instrumentation during fuzzing.

## Abstract interpretation view

Prevail computes invariants $A_L$ at program points $L$ (pre/post instruction labels). In practice, runtime observations are often incomplete:

- Sometimes an observer can provide a complete concrete state $\sigma$.
- More commonly, an observer provides a **partial observation** $o$ (only some registers, only pointer fields, only “changed” locations, etc.).

The check answers:

> “Is this observed execution (or partial observation of it) **ruled out** by the invariant at $L$?”

If it is ruled out, that is a strong signal of a semantic mismatch:
- the VM semantics (interpreter/JIT) may be wrong, or
- the abstract semantics (transfer function / constraints) may be wrong.

### Consistency vs entailment

Prevail supports two related checks (modes) when comparing an observation against an invariant:

1. **Consistency** (default): the observation is *not ruled out* by the invariant.
2. **Entailment** (stricter): the invariant *entails* the observation.

In abstract-interpretation terms, let:

- $A_L$ be the computed invariant at label $L$.
- $C_L$ be the abstract element produced from observation constraints.

Then:

- **Consistency** checks satisfiability (meet-not-bottom):

$$ (A_L \sqcap C_L) \neq \bot $$

- **Entailment** checks the lattice order:

$$ C_L \sqsubseteq A_L $$

Consistency is the default because partial observations naturally omit facts (which behave like $\top$), making entailment too strong for many practical observations.

## API

Prevail exposes this functionality via `prevail::AnalysisResult`.

```cpp
namespace prevail {

enum class InvariantPoint {
    pre,
    post,
};

enum class ObservationCheckMode {
    // Default: supports partial observations.
    consistent,
    // Optional: only useful when the observation is near-complete.
    entailed,
};

struct ObservationCheckResult {
    bool ok;
    std::string message;
};

struct AnalysisResult {
  // ... existing fields ...

  [[nodiscard]]
  ObservationCheckResult check_observation_at_label(
    const Label& label,
    InvariantPoint point,
    const StringInvariant& observation,
    ObservationCheckMode mode = ObservationCheckMode::consistent) const;

  [[nodiscard]]
  bool is_consistent_before(const Label& label, const StringInvariant& observation) const;

  [[nodiscard]]
  bool is_consistent_after(const Label& label, const StringInvariant& observation) const;
};

}
```

Semantics:
- Prevail converts `observation` constraints into an `EbpfDomain` element ($C_L$).
- Prevail selects the computed `pre`/`post` invariant as the abstract state ($A_L$).
- When `mode == ObservationCheckMode::consistent`, the check passes iff the meet is not bottom.
- When `mode == ObservationCheckMode::entailed`, the check passes iff the observation is entailed by the invariant.

When the observation constraints themselves are unsatisfiable (i.e., they map to bottom), the check fails and returns a diagnostic message.

## Labels and constraint format

- **Labels (YAML tests):** `at` is a scalar label: `entry`, `exit`, or an instruction index like `12`.
- **Constraints:** reuse the existing string constraint vocabulary already used by YAML tests.

An observation may be *partial*.
- Omitted constraints are fine (and common).
- Malformed constraints or self-contradictory constraints cause the observation check to fail.

## YAML integration

YAML tests support an optional `observe` section that specifies one or more observation checks to run against the computed invariants.

Schema (see `test-schema.yaml`):

- `observe`: sequence of maps
  - `at` (required): `entry`, `exit`, or instruction index
  - `constraints` (required): list of constraint strings
  - `point` (optional): `pre` (default) or `post`
  - `mode` (optional): `consistent` (default) or `entailed`

Example:

```yaml
observe:
  - at: entry
    point: pre
    mode: consistent
    constraints:
      - r1.type == map_value
  - at: 12
    point: post
    constraints:
      - r0.svalue == 0
```

## Diagnostics

On failure, `check_observation_at_label` returns `ok=false` with a short diagnostic message describing the reason (for example: unsatisfiable observation constraints, meet is bottom, or entailment does not hold).

## Soundness and scope

This feature is validation-only:
- It does not change verification outcomes.
- It provides a way to detect semantic mismatches by checking that observed behavior is not excluded by the computed invariant.

## Use cases

### VM/JIT instrumentation during fuzzing

An instrumented interpreter can emit partial observation constraints before/after an instruction and check them against the corresponding pre/post invariants.

### Regression tests that check intermediate states

YAML-driven tests can include intermediate observation points to assert that the analyzer’s invariants remain compatible with expected intermediate behavior.
