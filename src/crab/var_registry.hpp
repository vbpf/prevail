// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "arith/num_big.hpp"
#include "arith/variable.hpp"
#include "crab/type_encoding.hpp"

namespace prevail {

/// The fan of variables that describe one register: every field is
/// `VariableRegistry::reg(kind, i)` for the corresponding DataKind.
/// Produced by `VariableRegistry::reg_pack(i)`.
struct RegPack {
    Variable svalue; // int64_t value.
    Variable uvalue; // uint64_t value.
    Variable ctx_offset;
    Variable map_fd;
    Variable map_fd_programs;
    Variable packet_offset;
    Variable shared_offset;
    Variable stack_offset;
    Variable shared_region_size;
    Variable stack_numeric_size;
    Variable socket_offset;
    Variable btf_id_offset;
    Variable alloc_mem_offset;
    Variable alloc_mem_size;
};

// Variables are represented throughout the domains as compact interned ids
// rather than as structured eBPF variable keys. The registry owns the mapping
// between canonical variable descriptions and ids, and provides the eBPF-specific
// constructors/classifiers for those descriptions.
//
// The registry is stored thread-locally, so `intern`'s append path has no
// concurrency concerns on the current design. Sharing a registry across
// threads would require synchronization on `names`.
class VariableRegistry final {
    Variable intern(const std::string& name) const;
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

    /// All variables associated with register `i`. A bulk version of `reg(kind, i)`.
    [[nodiscard]]
    RegPack reg_pack(int i) const;
};

/// Returns the per-thread VariableRegistry, constructing it on first access.
/// Uses function-local thread_local so construction is deferred until first
/// call rather than running in a TLS dynamic-init callback (which can race
/// with CRT startup when extra threads are created early, e.g. by ASan).
VariableRegistry& get_variable_registry();

} // namespace prevail

// Backward-compatible alias: all existing code uses `variable_registry.method()`.
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define variable_registry (::prevail::get_variable_registry())
