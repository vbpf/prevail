// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <algorithm>
#include <cassert>

#include <boost/dynamic_bitset.hpp>

#include "config.hpp"
#include "string_constraints.hpp"

namespace prevail {
class BitsetDomain final {
  private:
    using bits_t = boost::dynamic_bitset<>;
    bits_t non_numerical_bytes;

  public:
    // Top at the requested size. (`set()` = all non-numerical = no knowledge about any byte.)
    explicit BitsetDomain(const size_t size) : non_numerical_bytes(size) { non_numerical_bytes.set(); }

    explicit BitsetDomain(bits_t non_numerical_bytes) noexcept : non_numerical_bytes{std::move(non_numerical_bytes)} {}
    BitsetDomain(const BitsetDomain&) = default;
    BitsetDomain(BitsetDomain&&) noexcept = default;
    BitsetDomain& operator=(const BitsetDomain&) = default;
    BitsetDomain& operator=(BitsetDomain&&) noexcept = default;

    // BitsetDomain has no bottom of its own; bottom for a container that
    // needs one is represented externally (e.g. wrapping the stack in
    // std::optional inside EbpfDomain).
    void set_to_top() noexcept { non_numerical_bytes.set(); }

    [[nodiscard]]
    bool is_top() const noexcept {
        return non_numerical_bytes.all();
    }

    [[nodiscard]]
    StringInvariant to_set() const;

    bool operator<=(const BitsetDomain& other) const {
        assert(non_numerical_bytes.size() == other.non_numerical_bytes.size());
        return (non_numerical_bytes | other.non_numerical_bytes) == other.non_numerical_bytes;
    }

    bool operator==(const BitsetDomain& other) const {
        assert(non_numerical_bytes.size() == other.non_numerical_bytes.size());
        return non_numerical_bytes == other.non_numerical_bytes;
    }

    void operator|=(const BitsetDomain& other) {
        assert(non_numerical_bytes.size() == other.non_numerical_bytes.size());
        non_numerical_bytes |= other.non_numerical_bytes;
    }

    BitsetDomain operator|(const BitsetDomain& other) const {
        assert(non_numerical_bytes.size() == other.non_numerical_bytes.size());
        return BitsetDomain{non_numerical_bytes | other.non_numerical_bytes};
    }

    BitsetDomain operator&(const BitsetDomain& other) const {
        assert(non_numerical_bytes.size() == other.non_numerical_bytes.size());
        return BitsetDomain{non_numerical_bytes & other.non_numerical_bytes};
    }

    [[nodiscard]]
    BitsetDomain widen(const BitsetDomain& other) const {
        assert(non_numerical_bytes.size() == other.non_numerical_bytes.size());
        return BitsetDomain{non_numerical_bytes | other.non_numerical_bytes};
    }

    [[nodiscard]]
    BitsetDomain narrow(const BitsetDomain& other) const {
        assert(non_numerical_bytes.size() == other.non_numerical_bytes.size());
        return BitsetDomain{non_numerical_bytes & other.non_numerical_bytes};
    }

    [[nodiscard]]
    std::pair<bool, bool> uniformity(const size_t lb, int width) const noexcept {
        if (lb >= non_numerical_bytes.size()) {
            return {true, true};
        }
        width = std::min(width, gsl::narrow_cast<int>(non_numerical_bytes.size() - lb));
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
        if (lb >= non_numerical_bytes.size()) {
            return 0;
        }
        size_t ub = lb;
        while (ub < non_numerical_bytes.size() && !non_numerical_bytes[ub]) {
            ub++;
        }
        return static_cast<int>(ub - lb);
    }

    void reset(const size_t lb, int n) noexcept {
        if (lb >= non_numerical_bytes.size()) {
            return;
        }
        n = std::min(n, gsl::narrow_cast<int>(non_numerical_bytes.size() - lb));
        for (int i = 0; i < n; i++) {
            non_numerical_bytes.reset(lb + i);
        }
    }

    void havoc(const size_t lb, int width) noexcept {
        if (lb >= non_numerical_bytes.size()) {
            return;
        }
        width = std::min(width, static_cast<int>(non_numerical_bytes.size() - lb));
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
        ub = std::min(ub, gsl::narrow_cast<int32_t>(non_numerical_bytes.size()));
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
