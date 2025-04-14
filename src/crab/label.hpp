// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <algorithm>
#include <cinttypes>
#include <climits>
#include <functional>
#include <limits>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "crab_utils/num_safety.hpp"

constexpr char STACK_FRAME_DELIMITER = '/';

namespace prevail {
struct label_t {
    std::string stack_frame_prefix; ///< Variable prefix when calling this label.
    int from{};                     ///< Jump source, or simply index of instruction
    int to{};                       ///< Jump target or -1
    std::string special_label;      ///< Special label for special instructions.

    explicit label_t(const int index, const int to = -1, std::string stack_frame_prefix = {}) noexcept
        : stack_frame_prefix(std::move(stack_frame_prefix)), from(index), to(to) {}

    static label_t make_jump(const label_t& src_label, const label_t& target_label) {
        return label_t{src_label.from, target_label.from, target_label.stack_frame_prefix};
    }

    static label_t make_increment_counter(const label_t& label) {
        // XXX: This is a hack to increment the loop counter.
        label_t res{label.from, label.to, label.stack_frame_prefix};
        res.special_label = "counter";
        return res;
    }

    std::strong_ordering operator<=>(const label_t& other) const = default;

    // no hash; intended for use in ordered containers.

    [[nodiscard]]
    constexpr bool isjump() const {
        return to != -1;
    }

    [[nodiscard]]
    int call_stack_depth() const {
        // The call stack depth is the number of '/' separated components in the label,
        // which is one more than the number of '/' separated components in the prefix,
        // hence two more than the number of '/' in the prefix, if any.
        if (stack_frame_prefix.empty()) {
            return 1;
        }
        return gsl::narrow<int>(2 + std::ranges::count(stack_frame_prefix, STACK_FRAME_DELIMITER));
    }

    static const label_t entry;
    static const label_t exit;
};

inline const label_t label_t::entry{-1};
inline const label_t label_t::exit{INT_MAX};

std::ostream& operator<<(std::ostream& os, const label_t& label);
std::string to_string(label_t const& label);

// cpu=v4 supports 32-bit PC offsets so we need a large enough type.
using pc_t = uint32_t;

// We use a 16-bit offset whenever it fits in 16 bits.
inline std::function<int16_t(label_t)> label_to_offset16(const pc_t pc) {
    return [=](const label_t& label) {
        const int64_t offset = label.from - gsl::narrow<int64_t>(pc) - 1;
        const bool is16 =
            std::numeric_limits<int16_t>::min() <= offset && offset <= std::numeric_limits<int16_t>::max();
        return gsl::narrow<int16_t>(is16 ? offset : 0);
    };
}

// We use the JA32 opcode with the offset in 'imm' when the offset
// of an unconditional jump doesn't fit in an int16_t.
inline std::function<int32_t(label_t)> label_to_offset32(const pc_t pc) {
    return [=](const label_t& label) {
        const int64_t offset = label.from - gsl::narrow<int64_t>(pc) - 1;
        const bool is16 =
            std::numeric_limits<int16_t>::min() <= offset && offset <= std::numeric_limits<int16_t>::max();
        return is16 ? 0 : gsl::narrow<int32_t>(offset);
    };
}

} // namespace prevail
