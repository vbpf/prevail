# Prevail eBPF Verifier Documentation

This documentation provides a comprehensive guide to understanding the Prevail eBPF verifier codebase.

## Quick Links

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | High-level system architecture and component overview |
| [Abstract Interpretation](abstract-interpretation.md) | Core verification approach and fixpoint computation |
| [Abstract Domains](abstract-domains.md) | Crab abstract domain hierarchy and implementation |
| [Instruction Semantics](instruction-semantics.md) | How eBPF instructions are modeled and verified |
| [Control Flow Graph](cfg.md) | CFG construction and weak topological ordering |
| [Memory Model](memory-model.md) | Stack, packet, context, and shared memory handling |
| [Type System](type-system.md) | Type domains and type-guided verification |
| [Failure Slicing](failure-slicing.md) | Minimal diagnostic slices for verification failures |
| [Building](building.md) | Build instructions for all platforms |
| [Testing](testing.md) | Test infrastructure and conformance testing |
| [Glossary](glossary.md) | Terminology and definitions |
| [LLM Context](llm-context.md) | Guide for LLM-assisted failure diagnosis |

## What is Prevail?

Prevail is a static analyzer for eBPF (extended Berkeley Packet Filter) bytecode programs. It uses **abstract interpretation** to prove memory safety and type safety properties without executing the program.

### Key Features

- **Sound verification**: If Prevail accepts a program, it is guaranteed to be safe
- **Precise analysis**: Uses relational numeric domains (difference-bound matrices) for accurate tracking
- **Type-guided precision**: Combines type information with numeric constraints
- **Loop handling**: Automatic widening/narrowing with bounded loop verification
- **Platform support**: Windows, Linux, macOS

### Verification Goals

Prevail verifies that eBPF programs:

1. **Never access out-of-bounds memory** (stack, packet, context, maps)
2. **Never dereference null pointers**
3. **Never use uninitialized data**
4. **Respect type constraints** (e.g., don't treat numbers as pointers)
5. **Terminate** (bounded loop iteration)
6. **Follow calling conventions** (helper function signatures)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        ELF Binary Input                         │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ELF Loader & Unmarshaller                    │
│              (elf_loader.cpp, unmarshal.cpp)                    │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Instruction Sequence                        │
│                        (src/ir/syntax.hpp)                      │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                CFG Builder + Assertion Generator                │
│                      (src/ir/cfg_builder.cpp)                   │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Program (CFG + Assertions)                   │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Forward Fixpoint Iterator (WTO-based)              │
│                      (src/fwd_analyzer.cpp)                     │
│  ┌──────────────┐    ┌─────────────────┐    ┌──────────────┐    │
│  │ EbpfDomain   │◄──►│ EbpfTransformer │◄──►│ EbpfChecker  │    │
│  │ (state)      │    │ (semantics)     │    │ (assertions) │    │
│  └──────────────┘    └─────────────────┘    └──────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Analysis Result                           │
│           (invariants, errors, loop bounds, exit value)         │
└─────────────────────────────────────────────────────────────────┘
```

## Source Code Organization

```text
src/
├── main/           # Entry points (check.cpp - CLI verifier)
├── ir/             # Intermediate representation
│   ├── syntax.hpp  # Instruction definitions
│   └── cfg_builder.cpp
├── cfg/            # Control flow graph
│   ├── cfg.hpp     # Graph structure
│   └── wto.hpp     # Weak topological ordering
├── crab/           # Abstract interpretation core
│   ├── ebpf_domain.hpp      # Main composite domain
│   ├── ebpf_transformer.cpp # Instruction semantics
│   ├── ebpf_checker.cpp     # Assertion checking
│   └── zone_domain.hpp      # Numeric domain (zone abstract domain)
├── crab_utils/     # Domain utilities
├── arith/          # Arithmetic helpers
├── linux/          # Linux-specific platform code
└── test/           # Test infrastructure
```

## Getting Started

1. **Build the verifier**: See [Building](building.md)
2. **Run on an ELF file**: `./bin/check path/to/program.o section/function`
3. **Understand the output**: The verifier prints invariants and any errors found

## Further Reading

- [RFC 9669](https://www.rfc-editor.org/rfc/rfc9669.html) - BPF Instruction Set Architecture
- Cousot & Cousot (1977) - Abstract Interpretation foundations
- Bourdoncle (1993) - Efficient chaotic iteration strategies (WTO)

## LLM-Assisted Diagnosis

When verification fails, you can use an LLM to help diagnose the issue.

**Quick start** (with GitHub Copilot CLI):

```text
Using docs/llm-context.md, run ./bin/check <your-program.o> <section> -v and diagnose the failure.
```

**Manual approach** (with any LLM):
1. Run the verifier with verbose output: `./bin/check program.o section -v`
2. Copy the contents of `docs/llm-context.md` into your LLM conversation
3. Paste the verification error and ask for diagnosis

See [llm-context.md](llm-context.md) for the context document and [test-data/llm-context-tests.md](../test-data/llm-context-tests.md) for validated test cases.

### Contributing New Failure Patterns

When you discover a verification failure that isn't covered by the existing patterns in Section 4 of `llm-context.md`, please contribute it:

1. **Identify the pattern**: Run `./bin/check <sample> <section> -v` and capture the error message and pre-invariant
2. **Add to Section 4**: Create a new subsection (e.g., `### 4.12 <Pattern Name>`) following the existing format:
   - **Symptom**: The error message text
   - **Red Flags**: Key invariant properties that indicate this failure
   - **Cause**: Why the verifier rejects this
   - **Fix**: How to resolve the issue (code changes or workarounds)
3. **Add a test case**: Add a corresponding test to `test-data/llm-context-tests.md` with:
   - The command to reproduce
   - Expected error message
   - Pattern reference
   - Key invariant to look for
4. **If needed, add a test sample**: If no existing sample triggers the error, add source to `ebpf-samples/src/` and update `ebpf-samples/CMakeLists.txt`

The goal is for LLMs to recognize the failure pattern and suggest the correct fix based on the documented context.
