// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/*
 * Factories for variable names.
 */

#include "crab/var_registry.hpp"
#include "arith/variable.hpp"
#include "cfg/label.hpp"
#include "crab_utils/lazy_allocator.hpp"

namespace prevail {

Variable VariableRegistry::make(const std::string& name) {
    const auto it = std::ranges::find(names, name);
    if (it == names.end()) {
        names.emplace_back(name);
        return Variable(names.size() - 1);
    }
    return Variable(std::distance(names.begin(), it));
}

static std::vector<std::string> default_variable_names() {
    return std::vector<std::string>{
        "r0.svalue",
        "r0.uvalue",
        "r0.ctx_offset",
        "r0.map_fd",
        "r0.packet_offset",
        "r0.shared_offset",
        "r0.stack_offset",
        "r0.type",
        "r0.shared_region_size",
        "r0.stack_numeric_size",
        "r1.svalue",
        "r1.uvalue",
        "r1.ctx_offset",
        "r1.map_fd",
        "r1.packet_offset",
        "r1.shared_offset",
        "r1.stack_offset",
        "r1.type",
        "r1.shared_region_size",
        "r1.stack_numeric_size",
        "r2.svalue",
        "r2.uvalue",
        "r2.ctx_offset",
        "r2.map_fd",
        "r2.packet_offset",
        "r2.shared_offset",
        "r2.stack_offset",
        "r2.type",
        "r2.shared_region_size",
        "r2.stack_numeric_size",
        "r3.svalue",
        "r3.uvalue",
        "r3.ctx_offset",
        "r3.map_fd",
        "r3.packet_offset",
        "r3.shared_offset",
        "r3.stack_offset",
        "r3.type",
        "r3.shared_region_size",
        "r3.stack_numeric_size",
        "r4.svalue",
        "r4.uvalue",
        "r4.ctx_offset",
        "r4.map_fd",
        "r4.packet_offset",
        "r4.shared_offset",
        "r4.stack_offset",
        "r4.type",
        "r4.shared_region_size",
        "r4.stack_numeric_size",
        "r5.svalue",
        "r5.uvalue",
        "r5.ctx_offset",
        "r5.map_fd",
        "r5.packet_offset",
        "r5.shared_offset",
        "r5.stack_offset",
        "r5.type",
        "r5.shared_region_size",
        "r5.stack_numeric_size",
        "r6.svalue",
        "r6.uvalue",
        "r6.ctx_offset",
        "r6.map_fd",
        "r6.packet_offset",
        "r6.shared_offset",
        "r6.stack_offset",
        "r6.type",
        "r6.shared_region_size",
        "r6.stack_numeric_size",
        "r7.svalue",
        "r7.uvalue",
        "r7.ctx_offset",
        "r7.map_fd",
        "r7.packet_offset",
        "r7.shared_offset",
        "r7.stack_offset",
        "r7.type",
        "r7.shared_region_size",
        "r7.stack_numeric_size",
        "r8.svalue",
        "r8.uvalue",
        "r8.ctx_offset",
        "r8.map_fd",
        "r8.packet_offset",
        "r8.shared_offset",
        "r8.stack_offset",
        "r8.type",
        "r8.shared_region_size",
        "r8.stack_numeric_size",
        "r9.svalue",
        "r9.uvalue",
        "r9.ctx_offset",
        "r9.map_fd",
        "r9.packet_offset",
        "r9.shared_offset",
        "r9.stack_offset",
        "r9.type",
        "r9.shared_region_size",
        "r9.stack_numeric_size",
        "r10.svalue",
        "r10.uvalue",
        "r10.ctx_offset",
        "r10.map_fd",
        "r10.packet_offset",
        "r10.shared_offset",
        "r10.stack_offset",
        "r10.type",
        "r10.shared_region_size",
        "r10.stack_numeric_size",
        "data_size",
        "meta_size",
        "meta_offset",
        "packet_size",
    };
}

VariableRegistry::VariableRegistry() : names(default_variable_names()) {}

thread_local LazyAllocator<VariableRegistry> variable_registry;

std::ostream& operator<<(std::ostream& o, const Variable& v) { return o << variable_registry->name(v); }

std::ostream& operator<<(std::ostream& o, const DataKind& s) { return o << name_of(s); }

Variable VariableRegistry::reg(const DataKind kind, const int i) {
    return make("r" + std::to_string(i) + "." + name_of(kind));
}

Variable VariableRegistry::type_reg(const int i) {
    return make("r" + std::to_string(i) + "." + name_of(DataKind::types));
}

Variable VariableRegistry::stack_frame_var(const DataKind kind, const int i, const std::string& prefix) {
    return make(prefix + STACK_FRAME_DELIMITER + "r" + std::to_string(i) + "." + name_of(kind));
}

static std::string mk_scalar_name(const DataKind kind, const Number& o, const Number& size) {
    std::stringstream os;
    os << "s" << "[" << o;
    if (size != 1) {
        os << "..." << o + size - 1;
    }
    os << "]." << name_of(kind);
    return os.str();
}

Variable VariableRegistry::cell_var(const DataKind array, const Number& offset, const Number& size) {
    return make(mk_scalar_name(array, offset.cast_to<uint64_t>(), size));
}

// Given a type variable, get the associated variable of a given kind.
Variable VariableRegistry::kind_var(const DataKind kind, const Variable type_variable) {
    const std::string name = VariableRegistry::name(type_variable);
    const auto dot_pos = name.rfind('.');
    if (dot_pos == std::string::npos) {
        CRAB_ERROR("Variable name '", name, "' does not contain a dot");
    }
    return make(name.substr(0, dot_pos + 1) + name_of(kind));
}

Variable VariableRegistry::meta_offset() { return make("meta_offset"); }
Variable VariableRegistry::packet_size() { return make("packet_size"); }

bool VariableRegistry::is_min_only(const Variable& v) const {
    const auto& n = name(v);
    return n.ends_with(".stack_numeric_size") || n.ends_with(".shared_region_size") || n == "packet_size";
}

Variable VariableRegistry::loop_counter(const std::string& label) { return make("pc[" + label + "]"); }

static bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && 0 == str.compare(str.size() - suffix.size(), suffix.size(), suffix);
}

std::vector<Variable> VariableRegistry::get_type_variables() {
    std::vector<Variable> res;
    for (const std::string& name : names) {
        if (ends_with(name, ".type")) {
            res.push_back(make(name));
        }
    }
    return res;
}

std::string VariableRegistry::name(const Variable& v) const { return names.at(v._id); }

[[nodiscard]]
bool VariableRegistry::is_type(const Variable& v) const {
    return name(v).ends_with(".type");
}

[[nodiscard]]
bool VariableRegistry::is_unsigned(const Variable& v) const {
    return name(v).ends_with(".uvalue");
}

bool VariableRegistry::is_in_stack(const Variable& v) const { return name(v)[0] == 's'; }

bool VariableRegistry::printing_order(const Variable& a, const Variable& b) {
    return variable_registry->name(a) < variable_registry->name(b);
}

std::vector<Variable> VariableRegistry::get_loop_counters() {
    std::vector<Variable> res;
    for (const std::string& name : names) {
        if (name.starts_with("pc")) {
            res.push_back(make(name));
        }
    }
    return res;
}
} // end namespace prevail
