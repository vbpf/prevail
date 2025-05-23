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
class VariableRegistry final {
    Variable make(const std::string& name);
    std::vector<std::string> names;

  public:
    VariableRegistry();

    [[nodiscard]]
    std::string name(const Variable& v) const;

    [[nodiscard]]
    bool is_type(const Variable& v) const;

    [[nodiscard]]
    bool is_unsigned(const Variable& v) const;

    [[nodiscard]]
    bool is_in_stack(const Variable& v) const;

    std::vector<Variable> get_type_variables();
    Variable reg(DataKind, int);
    Variable stack_frame_var(DataKind kind, int i, const std::string& prefix);
    Variable cell_var(DataKind array, const Number& offset, const Number& size);
    Variable kind_var(DataKind kind, Variable type_variable);
    Variable meta_offset();
    Variable packet_size();
    std::vector<Variable> get_loop_counters();
    Variable loop_counter(const std::string& label);
    static bool printing_order(const Variable& a, const Variable& b);
};

extern thread_local LazyAllocator<VariableRegistry> variable_registry;

} // namespace prevail
