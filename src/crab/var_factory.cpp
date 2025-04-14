// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/*
 * Factories for variable names.
 */

#include "crab/label.hpp"
#include "crab/variable.hpp"
#include "crab_utils/lazy_allocator.hpp"

namespace prevail {

variable_t variable_t::make(const std::string& name) {
    const auto it = std::find(names->begin(), names->end(), name);
    if (it == names->end()) {
        names->emplace_back(name);
        return variable_t(names->size() - 1);
    }
    return variable_t(std::distance(names->begin(), it));
}

std::vector<std::string> default_variable_names() {
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
    };
}

thread_local lazy_allocator<std::vector<std::string>, default_variable_names> variable_t::names;

void variable_t::clear_thread_local_state() { names.clear(); }

variable_t variable_t::reg(const data_kind_t kind, const int i) {
    return make("r" + std::to_string(i) + "." + name_of(kind));
}

std::ostream& operator<<(std::ostream& o, const data_kind_t& s) { return o << name_of(s); }

static std::string mk_scalar_name(const data_kind_t kind, const number_t& o, const number_t& size) {
    std::stringstream os;
    os << "s" << "[" << o;
    if (size != 1) {
        os << "..." << o + size - 1;
    }
    os << "]." << name_of(kind);
    return os.str();
}

variable_t variable_t::stack_frame_var(const data_kind_t kind, const int i, const std::string& prefix) {
    return make(prefix + STACK_FRAME_DELIMITER + "r" + std::to_string(i) + "." + name_of(kind));
}

variable_t variable_t::cell_var(const data_kind_t array, const number_t& offset, const number_t& size) {
    return make(mk_scalar_name(array, offset.cast_to<uint64_t>(), size));
}

// Given a type variable, get the associated variable of a given kind.
variable_t variable_t::kind_var(const data_kind_t kind, const variable_t type_variable) {
    const std::string name = type_variable.name();
    return make(name.substr(0, name.rfind('.') + 1) + name_of(kind));
}

variable_t variable_t::meta_offset() { return make("meta_offset"); }
variable_t variable_t::packet_size() { return make("packet_size"); }
variable_t variable_t::loop_counter(const std::string& label) { return make("pc[" + label + "]"); }

static bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && 0 == str.compare(str.size() - suffix.size(), suffix.size(), suffix);
}

std::vector<variable_t> variable_t::get_type_variables() {
    std::vector<variable_t> res;
    for (const std::string& name : *names) {
        if (ends_with(name, ".type")) {
            res.push_back(make(name));
        }
    }
    return res;
}

bool variable_t::is_in_stack() const { return this->name()[0] == 's'; }

bool variable_t::printing_order(const variable_t& a, const variable_t& b) { return a.name() < b.name(); }

std::vector<variable_t> variable_t::get_loop_counters() {
    std::vector<variable_t> res;
    for (const std::string& name : *names) {
        if (name.find("pc") == 0) {
            res.push_back(make(name));
        }
    }
    return res;
}
} // end namespace prevail
