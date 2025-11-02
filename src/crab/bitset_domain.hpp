// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <algorithm>
#include <bitset>
#include <cassert>

#include "spec/ebpf_base.h"
#include "string_constraints.hpp"

namespace prevail {
class BitsetDomain final {
  private:
    using bits_t = std::bitset<EBPF_TOTAL_STACK_SIZE>;
    bits_t non_numerical_bytes;

  public:
    BitsetDomain() noexcept { non_numerical_bytes.set(); }

    // no performant move constructor to std::bitset, and therefore no copy-then-move for BitsetDomain
    explicit BitsetDomain(const bits_t& non_numerical_bytes) noexcept : non_numerical_bytes{non_numerical_bytes} {}
    BitsetDomain(const BitsetDomain& non_numerical_bytes) = default;

    // This is just to make the compiler happy in certain situations
    BitsetDomain(BitsetDomain&& non_numerical_bytes) = default;
    BitsetDomain& operator=(const BitsetDomain&) noexcept = default;
    BitsetDomain& operator=(BitsetDomain&&) noexcept = default;

    void set_to_top() noexcept { non_numerical_bytes.set(); }

    void set_to_bottom() noexcept { non_numerical_bytes.reset(); }

    [[nodiscard]]
    bool is_top() const noexcept {
        return non_numerical_bytes.all();
    }

    [[nodiscard]]
    bool is_bottom() const noexcept {
        return false;
    }

    [[nodiscard]]
    StringInvariant to_set() const;

    bool operator<=(const BitsetDomain& other) const noexcept {
        return (non_numerical_bytes | other.non_numerical_bytes) == other.non_numerical_bytes;
    }

    bool operator==(const BitsetDomain& other) const noexcept {
        return non_numerical_bytes == other.non_numerical_bytes;
    }

    void operator|=(const BitsetDomain& other) noexcept { non_numerical_bytes |= other.non_numerical_bytes; }

    BitsetDomain operator|(const BitsetDomain& other) const noexcept {
        return BitsetDomain{non_numerical_bytes | other.non_numerical_bytes};
    }

    BitsetDomain operator&(const BitsetDomain& other) const noexcept {
        return BitsetDomain{non_numerical_bytes & other.non_numerical_bytes};
    }

    [[nodiscard]]
    BitsetDomain widen(const BitsetDomain& other) const noexcept {
        return BitsetDomain{non_numerical_bytes | other.non_numerical_bytes};
    }

    [[nodiscard]]
    BitsetDomain narrow(const BitsetDomain& other) const noexcept {
        return BitsetDomain{non_numerical_bytes & other.non_numerical_bytes};
    }

    [[nodiscard]]
    std::pair<bool, bool> uniformity(const size_t lb, int width) const noexcept {
        if (lb >= EBPF_TOTAL_STACK_SIZE) {
            return {true, true};
        }
        width = std::min(width, gsl::narrow_cast<int>(EBPF_TOTAL_STACK_SIZE - lb));
        bool only_num = true;
        bool only_non_num = true;
        for (int j = 0; j < width; j++) {
            const bool b = non_numerical_bytes[lb + j]; // unchecked by design
            only_num &= !b;
            only_non_num &= b;
        }
        return std::make_pair(only_num, only_non_num);
    }

    // Get the number of bytes, starting at lb, known to be numbers.
    [[nodiscard]]
    int all_num_width(const size_t lb) const noexcept {
        if (lb >= EBPF_TOTAL_STACK_SIZE) {
            return 0;
        }
        size_t ub = lb;
        while (ub < EBPF_TOTAL_STACK_SIZE && !non_numerical_bytes[ub]) {
            ub++;
        }
        return static_cast<int>(ub - lb);
    }

    void reset(const size_t lb, int n) noexcept {
        if (lb >= EBPF_TOTAL_STACK_SIZE) {
            return;
        }
        n = std::min(n, gsl::narrow_cast<int>(EBPF_TOTAL_STACK_SIZE - lb));
        for (int i = 0; i < n; i++) {
            non_numerical_bytes.reset(lb + i);
        }
    }

    void havoc(const size_t lb, int width) noexcept {
        if (lb >= EBPF_TOTAL_STACK_SIZE) {
            return;
        }
        width = std::min(width, static_cast<int>(EBPF_TOTAL_STACK_SIZE - lb));
        for (int i = 0; i < width; i++) {
            non_numerical_bytes.set(lb + i);
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const BitsetDomain& b);

    // Test whether all values in the range [lb,ub) are numerical.
    [[nodiscard]]
    bool all_num(int32_t lb, int32_t ub) const noexcept {
        if (lb == ub) {
            return true;
        }
        lb = std::max(lb, 0);
        ub = std::min(ub, EBPF_TOTAL_STACK_SIZE);
        assert(lb <= ub);

        for (int i = lb; i < ub; i++) {
            if (non_numerical_bytes[i]) {
                return false;
            }
        }
        return true;
    }
};
} // namespace prevail
