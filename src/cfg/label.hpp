// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <algorithm>
#include <cinttypes>
#include <climits>
#include <functional>
#include <limits>
#include <string>
#include <utility>

#include "crab_utils/num_safety.hpp"

namespace prevail {

constexpr char STACK_FRAME_DELIMITER = '/';

struct Label {
    std::string stack_frame_prefix; ///< Variable prefix when calling this label.
    int from{};                     ///< Jump source, or simply index of instruction
    int to{};                       ///< Jump target or -1
    std::string special_label;      ///< Special label for special instructions.

    explicit Label(const int index, const int to = -1, std::string stack_frame_prefix = {}) noexcept
        : stack_frame_prefix(std::move(stack_frame_prefix)), from(index), to(to) {}

    static Label make_jump(const Label& src_label, const Label& target_label) {
        return Label{src_label.from, target_label.from, target_label.stack_frame_prefix};
    }

    static Label make_increment_counter(const Label& label) {
        // XXX: This is a hack to increment the loop counter.
        Label res{label.from, label.to, label.stack_frame_prefix};
        res.special_label = "counter";
        return res;
    }

    std::strong_ordering operator<=>(const Label& other) const = default;

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

    static const Label entry;
    static const Label exit;
};

inline const Label Label::entry{-1};
inline const Label Label::exit{INT_MAX};

std::ostream& operator<<(std::ostream& os, const Label& label);
std::string to_string(Label const& label);

// cpu=v4 supports 32-bit PC offsets so we need a large enough type.
using Pc = uint32_t;

// We use a 16-bit offset whenever it fits in 16 bits.
inline std::function<int16_t(Label)> label_to_offset16(const Pc pc) {
    return [=](const Label& label) {
        const int64_t offset = label.from - gsl::narrow<int64_t>(pc) - 1;
        const bool is16 =
            std::numeric_limits<int16_t>::min() <= offset && offset <= std::numeric_limits<int16_t>::max();
        return gsl::narrow<int16_t>(is16 ? offset : 0);
    };
}

// We use the JA32 opcode with the offset in 'imm' when the offset
// of an unconditional jump doesn't fit in an int16_t.
inline std::function<int32_t(Label)> label_to_offset32(const Pc pc) {
    return [=](const Label& label) {
        const int64_t offset = label.from - gsl::narrow<int64_t>(pc) - 1;
        const bool is16 =
            std::numeric_limits<int16_t>::min() <= offset && offset <= std::numeric_limits<int16_t>::max();
        return is16 ? 0 : gsl::narrow<int32_t>(offset);
    };
}

} // namespace prevail
