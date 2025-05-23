// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <iosfwd>
#include <vector>

#include "crab/type_encoding.hpp"
#include "crab_utils/lazy_allocator.hpp"
#include "num_big.hpp"

namespace prevail {

std::vector<std::string> default_variable_names();

// Wrapper for typed variables used by the abstract domains and linear_constraints.
// Being a class (instead of a type alias) enables overloading in dsl_syntax
class Variable final {
    friend struct VariableRegistry;
    uint64_t _id;

    explicit Variable(const uint64_t id) : _id(id) {}

  public:
    [[nodiscard]]
    std::size_t hash() const {
        return _id;
    }

    bool operator==(const Variable o) const { return _id == o._id; }

    bool operator!=(const Variable o) const { return (!(operator==(o))); }

    // for flat_map
    bool operator<(const Variable o) const { return _id < o._id; }

    friend std::ostream& operator<<(std::ostream& o, const Variable& v);

}; // class Variable

// This singleton is eBPF-specific, to avoid lifetime issues and/or passing factory explicitly everywhere.
// The state is VariableRegistry::names.
class VariableRegistry final {
    static Variable make(const std::string& name);

    /**
     * @brief Factory to always return the initial variable names.
     *
     * @tparam[in] T Should always be std::vector<std::string>.
     */
    static thread_local LazyAllocator<std::vector<std::string>, default_variable_names> names;

  public:
    static void clear_thread_local_state();

    [[nodiscard]]
    static std::string name(const Variable& v);

    [[nodiscard]]
    static bool is_type(const Variable& v);

    [[nodiscard]]
    static bool is_unsigned(const Variable& v);

    static std::vector<Variable> get_type_variables();
    static Variable reg(DataKind, int);
    static Variable stack_frame_var(DataKind kind, int i, const std::string& prefix);
    static Variable cell_var(DataKind array, const Number& offset, const Number& size);
    static Variable kind_var(DataKind kind, Variable type_variable);
    static Variable meta_offset();
    static Variable packet_size();
    static std::vector<Variable> get_loop_counters();
    static Variable loop_counter(const std::string& label);
    static bool is_in_stack(const Variable& v);
    static bool printing_order(const Variable& a, const Variable& b);
};

} // namespace prevail
