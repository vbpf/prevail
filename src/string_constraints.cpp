// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <ostream>
#include <set>
#include <string>

#include "result.hpp"
#include "string_constraints.hpp"

namespace prevail {

std::set<std::string> StringInvariant::to_lines() const {
    if (is_bottom()) {
        return {"_|_"};
    }
    return *maybe_inv;
}

StringInvariant StringInvariant::operator+(const StringInvariant& b) const {
    if (this->is_bottom()) {
        return b;
    }
    if (b.is_bottom()) {
        return *this;
    }
    StringInvariant res = *this;
    for (const std::string& cst : b.value()) {
        if (!res.contains(cst)) {
            res.maybe_inv->insert(cst);
        }
    }
    return res;
}

std::ostream& operator<<(std::ostream& o, const StringInvariant& inv) {
    if (inv.is_bottom()) {
        return o << "_|_";
    }

    const RelevantState* filter = get_invariant_filter(o);

    bool first = true;
    o << "[";
    auto& set = inv.maybe_inv.value();
    std::string lastbase;
    for (const auto& item : set) {
        if (filter && !filter->is_relevant_constraint(item)) {
            continue;
        }

        if (first) {
            first = false;
        } else {
            o << ", ";
        }
        const size_t pos = item.find_first_of(".=[");
        std::string base = item.substr(0, pos);
        if (base != lastbase) {
            o << "\n    ";
            lastbase = base;
        }
        o << item;
    }
    o << "]";
    return o;
}

} // namespace prevail
