// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <cassert>
#include <memory>
#include <utility>

namespace prevail {

/// Copy-on-write wrapper. Const access (`*`, `->`) is free (shared);
/// mutable access (`get_mutable()`) detaches when the underlying object
/// is shared with other Cow instances.
///
/// Requires: T is copy-constructible (get_mutable detaches via copy).
/// Invariant: the internal shared_ptr is never null.
template <typename T>
class Cow final {
    std::shared_ptr<T> ptr_;

  public:
    explicit Cow(std::shared_ptr<T> p) : ptr_(std::move(p)) { assert(ptr_); }

    template <typename... Args>
    static Cow make(Args&&... args) {
        return Cow{std::make_shared<T>(std::forward<Args>(args)...)};
    }

    Cow(const Cow&) = default;
    Cow(Cow&&) noexcept = default;
    Cow& operator=(const Cow&) = default;
    Cow& operator=(Cow&&) noexcept = default;

    const T& operator*() const { return *ptr_; }
    const T* operator->() const { return ptr_.get(); }

    [[nodiscard]]
    T& get_mutable() {
        if (ptr_.use_count() > 1) {
            ptr_ = std::make_shared<T>(*ptr_);
        }
        return *ptr_;
    }

    const T* get() const { return ptr_.get(); }
};

} // namespace prevail
