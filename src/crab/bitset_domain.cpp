// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <ostream>

#include "bitset_domain.hpp"

std::ostream& operator<<(std::ostream& o, const bitset_domain_t& b) {
    o << "Numbers -> {";
    bool first = true;
    for (int i = -EBPF_TOTAL_STACK_SIZE; i < 0; i++) {
        if (b.non_numerical_bytes[EBPF_TOTAL_STACK_SIZE + i]) {
            continue;
        }
        if (!first) {
            o << ", ";
        }
        first = false;
        o << "[" << EBPF_TOTAL_STACK_SIZE + i;
        int j = i + 1;
        for (; j < 0; j++) {
            if (b.non_numerical_bytes[EBPF_TOTAL_STACK_SIZE + j]) {
                break;
            }
        }
        if (j > i + 1) {
            o << "..." << EBPF_TOTAL_STACK_SIZE + j - 1;
        }
        o << "]";
        i = j;
    }
    o << "}";
    return o;
}

string_invariant bitset_domain_t::to_set() const {
    if (this->is_bottom()) {
        return string_invariant::bottom();
    }
    if (this->is_top()) {
        return string_invariant::top();
    }

    std::set<std::string> result;
    for (int i = -EBPF_TOTAL_STACK_SIZE; i < 0; i++) {
        if (non_numerical_bytes[EBPF_TOTAL_STACK_SIZE + i]) {
            continue;
        }
        std::string value = "s[" + std::to_string(EBPF_TOTAL_STACK_SIZE + i);
        int j = i + 1;
        for (; j < 0; j++) {
            if (non_numerical_bytes[EBPF_TOTAL_STACK_SIZE + j]) {
                break;
            }
        }
        if (j > i + 1) {
            value += "..." + std::to_string(EBPF_TOTAL_STACK_SIZE + j - 1);
        }
        value += "].type=number";
        result.insert(value);
        i = j;
    }
    return string_invariant{result};
}