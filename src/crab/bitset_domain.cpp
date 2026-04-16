// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <ostream>
#include <string>

#include "crab/bitset_domain.hpp"

namespace prevail {
std::ostream& operator<<(std::ostream& o, const BitsetDomain& b) {
    const auto total = static_cast<int>(b.non_numerical_bytes.size());
    o << "Numbers -> {";
    bool first = true;
    for (int i = -total; i < 0; i++) {
        if (b.non_numerical_bytes[total + i]) {
            continue;
        }
        if (!first) {
            o << ", ";
        }
        first = false;
        o << "[" << total + i;
        int j = i + 1;
        for (; j < 0; j++) {
            if (b.non_numerical_bytes[total + j]) {
                break;
            }
        }
        if (j > i + 1) {
            o << "..." << total + j - 1;
        }
        o << "]";
        i = j;
    }
    o << "}";
    return o;
}

StringInvariant BitsetDomain::to_set() const {
    if (this->is_top()) {
        return StringInvariant::top();
    }

    const auto total = static_cast<int>(non_numerical_bytes.size());
    std::set<std::string> result;
    for (int i = -total; i < 0; i++) {
        if (non_numerical_bytes[total + i]) {
            continue;
        }
        std::string value = "s[" + std::to_string(total + i);
        int j = i + 1;
        for (; j < 0; j++) {
            if (non_numerical_bytes[total + j]) {
                break;
            }
        }
        if (j > i + 1) {
            value += "..." + std::to_string(total + j - 1);
        }
        value += "].type=number";
        result.insert(value);
        i = j;
    }
    return StringInvariant{std::move(result)};
}
} // namespace prevail