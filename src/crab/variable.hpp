// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <iosfwd>
#include <iostream>
#include <memory>
#include <vector>

#include "crab/type_encoding.hpp"
#include "crab_utils/lazy_allocator.hpp"
#include "crab_utils/num_big.hpp"

namespace prevail {

std::vector<std::string> default_variable_names();

// Wrapper for typed variables used by the abstract domains and linear_constraints.
// Being a class (instead of a type alias) enables overloading in dsl_syntax
class variable_t final {
    uint64_t _id;

    explicit variable_t(const uint64_t id) : _id(id) {}

  public:
    [[nodiscard]]
    std::size_t hash() const {
        return _id;
    }

    bool operator==(const variable_t o) const { return _id == o._id; }

    bool operator!=(const variable_t o) const { return (!(operator==(o))); }

    // for flat_map
    bool operator<(const variable_t o) const { return _id < o._id; }

    [[nodiscard]]
    std::string name() const {
        return names->at(_id);
    }

    [[nodiscard]]
    bool is_type() const {
        return names->at(_id).find(".type") != std::string::npos;
    }

    [[nodiscard]]
    bool is_unsigned() const {
        return names->at(_id).find(".uvalue") != std::string::npos;
    }

    friend std::ostream& operator<<(std::ostream& o, const variable_t v) { return o << names->at(v._id); }

    // var_factory portion.
    // This singleton is eBPF-specific, to avoid lifetime issues and/or passing factory explicitly everywhere:
  private:
    static variable_t make(const std::string& name);

    /**
     * @brief Factory to always return the initial variable names.
     *
     * @tparam[in] T Should always be std::vector<std::string>.
     */
    static thread_local lazy_allocator<std::vector<std::string>, default_variable_names> names;

  public:
    static void clear_thread_local_state();

    static std::vector<variable_t> get_type_variables();
    static variable_t reg(data_kind_t, int);
    static variable_t stack_frame_var(data_kind_t kind, int i, const std::string& prefix);
    static variable_t cell_var(data_kind_t array, const number_t& offset, const number_t& size);
    static variable_t kind_var(data_kind_t kind, variable_t type_variable);
    static variable_t meta_offset();
    static variable_t packet_size();
    static std::vector<variable_t> get_loop_counters();
    static variable_t loop_counter(const std::string& label);
    [[nodiscard]]
    bool is_in_stack() const;
    static bool printing_order(const variable_t& a, const variable_t& b);
}; // class variable_t

} // namespace prevail
