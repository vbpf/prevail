// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "arith/num_big.hpp"
#include "arith/variable.hpp"
#include "crab/type_encoding.hpp"
#include "crab_utils/lazy_allocator.hpp"

namespace prevail {

// This singleton is eBPF-specific, to avoid lifetime issues and/or passing factory explicitly everywhere.
//
// The registry is a name-to-id memoization cache: `make(name)` returns the same
// `Variable` for the same name across the lifetime of a registry, whether or
// not `name` was already interned. The factory methods (`reg`, `cell_var`, ...)
// compose a canonical name and call `make`, so they are logically pure
// functions of their arguments. `names` is therefore declared `mutable` and all
// public methods are `const`: callers treat the registry as immutable state.
//
// The registry is stored thread-locally, so `make`'s append path has no
// concurrency concerns on the current design. Sharing a registry across
// threads would require synchronization on `names`.
class VariableRegistry final {
    Variable make(const std::string& name) const;
    mutable std::vector<std::string> names;

  public:
    VariableRegistry();

    // Copying would fork the name cache: two registries could then assign
    // different ids to the same name (or the same id to different names),
    // and since `Variable` is a bare index with no back-pointer, a Variable
    // from one registry would silently misinterpret against the other.
    // Move is fine — it transfers identity rather than duplicating it.
    VariableRegistry(const VariableRegistry&) = delete;
    VariableRegistry& operator=(const VariableRegistry&) = delete;
    VariableRegistry(VariableRegistry&&) = default;
    VariableRegistry& operator=(VariableRegistry&&) = default;

    [[nodiscard]]
    std::string name(const Variable& v) const;

    [[nodiscard]]
    bool is_type(const Variable& v) const;

    [[nodiscard]]
    bool is_unsigned(const Variable& v) const;

    [[nodiscard]]
    bool is_in_stack(const Variable& v) const;

    std::vector<Variable> get_type_variables() const;
    Variable reg(DataKind, int) const;
    Variable type_reg(int) const;
    Variable stack_frame_var(DataKind kind, int i, const std::string& prefix) const;
    Variable cell_var(DataKind array, const Number& offset, const Number& size) const;
    Variable kind_var(DataKind kind, Variable type_variable) const;
    Variable meta_offset() const;
    Variable packet_size() const;

    /// EXPERIMENTAL: Variables where only the lower bound is semantically meaningful.
    [[nodiscard]]
    bool is_min_only(const Variable& v) const;

    std::vector<Variable> get_loop_counters() const;
    Variable loop_counter(const std::string& label) const;
    static bool printing_order(const Variable& a, const Variable& b);
};

extern thread_local LazyAllocator<VariableRegistry> variable_registry;

} // namespace prevail
