// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>

namespace prevail {

/**
 * @brief Lazy allocator for objects of type T. The allocator does not allocate the object until it is first accessed.
 *
 * @tparam T The type of the object to allocate.
 * @tparam factory The factory function to use to create the object.
 * The default factory creates the object using the default constructor.
 * The caller can provide a custom factory to create the object in a specific way.
 */
template <typename T, T (*factory)() = nullptr>
class lazy_allocator {
    std::optional<T> _value;

  public:
    /**
     * @brief Get the currently allocated object or allocate it if it has not been allocated yet.
     *
     * @return The allocated object.
     */
    T& get() {
        if (!_value.has_value()) {
            if constexpr (factory != nullptr) {
                _value = factory();
            } else {
                _value = T{};
            }
        }
        return _value.value();
    }

    /**
     * @brief Delete the currently allocated object.
     */
    void clear() { _value.reset(); }

    /**
     * @brief Allocate the object using the value.
     *
     * @param[in] value The value to copy.
     */
    void set(T value) { _value = value; }

    // Ideally we would overload the . operator, but that is not possible
    // so we use -> instead and modify the callers from . to ->

    /**
     * @brief Get the currently allocated object or allocate it if it has not been allocated yet.
     *
     * @return The allocated object.
     */
    T* operator->() { return &get(); }

    /**
     * @brief Get the currently allocated object or allocate it if it has not been allocated yet.
     *
     * @return The allocated object.
     */
    T& operator*() { return get(); }

    /**
     * @brief Assign the value to the currently allocated object.
     *
     * @param[in] value The value to assign.
     * @return The allocated object.
     */
    T& operator=(const T& value) {
        _value.emplace(value);
        return get();
    }
};
} // namespace prevail
