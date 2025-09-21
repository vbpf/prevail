// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/*
 * Factories for variable names.
 */

#include "crab/var_registry.hpp"
#include "cfg/label.hpp"
#include "crab_utils/lazy_allocator.hpp"
#include "variable.hpp"

namespace prevail {

VariableRegistry::VariableRegistry() {}

thread_local LazyAllocator<VariableRegistry> variable_registry;

std::ostream& operator<<(std::ostream& o, const DataKind& s) { return o << name_of(s); }

ProgVar VariableRegistry::reg(const DataKind kind, const int i) { return make(Reg(i), kind); }

ProgVar VariableRegistry::stack_frame_var(const DataKind kind, const int i, const std::string& prefix) {
    return make(StackFrame(prefix, i), kind);
}

ProgVar VariableRegistry::cell_var(const DataKind array, const Number& offset, const Number& size) {
    return make(Cell{offset.narrow<Index>(), size.narrow<size_t>()}, array);
}

// Given a type variable, get the associated variable of a given kind.
ProgVar VariableRegistry::kind_var(const DataKind kind, const ProgVar& type_variable) {
    if (type_variable.kind != DataKind::types) {
        throw std::invalid_argument("Variable type must be of data type");
    }
    return make(type_variable.loc, kind);
}

ProgVar VariableRegistry::meta_offset() { return make(SpecialVar::META_SIZE, DataKind::uvalues); }
ProgVar VariableRegistry::packet_size() { return make(SpecialVar::PACKET_SIZE, DataKind::uvalues); }
ProgVar VariableRegistry::loop_counter(const std::string& label) { return make(LoopCounter(label), DataKind::uvalues); }

std::vector<ProgVar> VariableRegistry::get_type_variables() {
    std::vector<ProgVar> res;
    for (const ProgVar& var : vars) {
        if (var.kind == DataKind::types) {
            res.push_back(var);
        }
    }
    return res;
}

std::string VariableRegistry::name(const ProgVar& v) const { return v.to_string(); }

[[nodiscard]]
bool VariableRegistry::is_type(const ProgVar& v) const {
    return v.kind == DataKind::types;
}

[[nodiscard]]
bool VariableRegistry::is_unsigned(const ProgVar& v) const {
    return v.kind == DataKind::uvalues;
}

bool VariableRegistry::is_in_stack(const ProgVar& v) const { return name(v)[0] == 's'; }

bool VariableRegistry::printing_order(const ProgVar& a, const ProgVar& b) {
    return variable_registry->name(a) < variable_registry->name(b);
}

std::vector<ProgVar> VariableRegistry::get_loop_counters() {
    std::vector<ProgVar> res;
    for (const ProgVar& var : vars) {
        if (std::holds_alternative<LoopCounter>(var.loc.var)) {
            res.push_back(var);
        }
    }
    return res;
}
} // end namespace prevail
