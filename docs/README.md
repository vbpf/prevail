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
| [Building](building.md) | Build instructions for all platforms |
| [Testing](testing.md) | Test infrastructure and conformance testing |
| [Glossary](glossary.md) | Terminology and definitions |

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
│                        ELF Binary Input                          │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ELF Loader & Unmarshaller                     │
│              (elf_loader.cpp, asm_unmarshal.cpp)                 │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Instruction Sequence                         │
│                        (src/ir/syntax.hpp)                       │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                CFG Builder + Assertion Generator                 │
│                      (src/ir/cfg_builder.cpp)                    │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Program (CFG + Assertions)                    │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Forward Fixpoint Iterator (WTO-based)               │
│                      (src/fwd_analyzer.cpp)                      │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐    │
│  │  EbpfDomain   │◄──►│ EbpfTransformer│◄──►│  EbpfChecker  │    │
│  │  (state)      │    │ (semantics)    │    │ (assertions)  │    │
│  └───────────────┘    └───────────────┘    └───────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Analysis Result                            │
│           (invariants, errors, loop bounds, exit value)          │
└─────────────────────────────────────────────────────────────────┘
```

## Source Code Organization

```
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
│   └── split_dbm.hpp        # Numeric domain
├── crab_utils/     # Domain utilities
├── arith/          # Arithmetic helpers
├── linux/          # Linux-specific platform code
└── test/           # Test infrastructure
```

## Getting Started

1. **Build the verifier**: See [Building](building.md)
2. **Run on an ELF file**: `./check path/to/program.o section/function`
3. **Understand the output**: The verifier prints invariants and any errors found

## Further Reading

- [RFC 9669](https://www.rfc-editor.org/rfc/rfc9669.html) - BPF Instruction Set Architecture
- Cousot & Cousot (1977) - Abstract Interpretation foundations
- Bourdoncle (1993) - Efficient chaotic iteration strategies (WTO)
