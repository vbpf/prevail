// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <concepts>

#include <gsl/narrow>

namespace prevail {

template <typename T>
concept is_enum = std::is_enum_v<T>;

template <std::integral T>
using SwapSignedness = std::conditional_t<std::is_signed_v<T>, std::make_unsigned_t<T>, std::make_signed_t<T>>;

constexpr auto to_signed(std::unsigned_integral auto x) -> std::make_signed_t<decltype(x)> {
    return static_cast<std::make_signed_t<decltype(x)>>(x);
}

constexpr auto to_unsigned(std::signed_integral auto x) -> std::make_unsigned_t<decltype(x)> {
    return static_cast<std::make_unsigned_t<decltype(x)>>(x);
}

// a guard to ensure that the signedness of the result is the same as the input
constexpr auto keep_signed(std::signed_integral auto x) -> decltype(x) { return x; }

// a guard to ensure that the signedness of the result is the same as the input
constexpr auto keep_unsigned(std::unsigned_integral auto x) -> decltype(x) { return x; }
} // namespace prevail
