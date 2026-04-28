// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <stdexcept>
#include <string>

namespace prevail {

// Project-wide error hierarchy.
//
// One distinction is load-bearing today: bug vs runtime error.
//   RuntimeInputError — recoverable failure caused by external input
//                       (malformed ELF/BTF/bytecode/YAML, bad CLI args,
//                       missing files, etc.).
//   InternalError     — a Prevail bug: an invariant violation that should
//                       never trigger in correct execution.
//
// Sub-classifying RuntimeInputError further (filesystem, unsupported
// feature, invalid program structure, ...) is intentionally deferred:
// nothing in the codebase currently dispatches by sub-type, so adding
// them now would be speculative. The eventual error-handling policy may
// introduce them when handler differentiation justifies it.
//
// This header is deliberately small and dependency-free so that
// public-API-reachable headers (e.g. ir/program.hpp, io/elf_loader.hpp)
// can declare error subclasses without pulling in CRAB debug machinery.
class PrevailError : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

class RuntimeInputError : public PrevailError {
  public:
    using PrevailError::PrevailError;
};

class InternalError : public PrevailError {
  public:
    using PrevailError::PrevailError;
};

} // namespace prevail
