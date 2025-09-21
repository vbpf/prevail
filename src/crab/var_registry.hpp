// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <vector>

#include "arith/num_big.hpp"
#include "arith/progvar.hpp"
#include "crab/type_encoding.hpp"
#include "crab_utils/lazy_allocator.hpp"

namespace prevail {

// This singleton is eBPF-specific, to avoid lifetime issues and/or passing factory explicitly everywhere.
class VariableRegistry final {
    std::vector<ProgVar> vars;

    ProgVar make(auto... args) {
        ProgVar var{args...};
        const auto it = std::ranges::find(vars, var);
        if (it == vars.end()) {
            vars.emplace_back(var);
            return vars.at(vars.size() - 1);
        }
        return vars.at(std::distance(vars.begin(), it));
    }

  public:
    VariableRegistry();

    [[nodiscard]]
    std::string name(const ProgVar& v) const;

    [[nodiscard]]
    bool is_type(const ProgVar& v) const;

    [[nodiscard]]
    bool is_unsigned(const ProgVar& v) const;

    [[nodiscard]]
    bool is_in_stack(const ProgVar& v) const;

    std::vector<ProgVar> get_type_variables();
    ProgVar reg(DataKind, int);
    ProgVar stack_frame_var(DataKind kind, int i, const std::string& prefix);
    ProgVar cell_var(DataKind array, const Number& offset, const Number& size);
    ProgVar kind_var(DataKind kind, const ProgVar& type_variable);
    ProgVar meta_offset();
    ProgVar packet_size();
    std::vector<ProgVar> get_loop_counters();
    ProgVar loop_counter(const std::string& label);
    static bool printing_order(const ProgVar& a, const ProgVar& b);
};

extern thread_local LazyAllocator<VariableRegistry> variable_registry;

} // namespace prevail
