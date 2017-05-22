#pragma once

#include <variant>
#include <string>
#include <type_traits>
#include <stdexcept>

namespace bypasscore {

/**
 * @brief Lightweight error type carrying a message and optional error code.
 */
struct Error {
    std::string message;
    int code = 0;

    Error() = default;
    explicit Error(std::string msg, int c = 0)
        : message(std::move(msg)), code(c) {}

    explicit operator bool() const { return code != 0 || !message.empty(); }
};

/**
 * @brief Result<T, E> — a sum type representing either a success value or
 *        an error. Inspired by Rust's Result type.
 *
 * Usage:
 *   Result<int> r = 42;
 *   if (r) { use(*r); }
 *
 *   Result<int> e = make_error("something failed", -1);
 *   if (!e) { log(e.error().message); }
 */
template <typename T, typename E = Error>
class Result {
public:
    Result(const T& value) : storage_(value) {}
    Result(T&& value) : storage_(std::move(value)) {}
    Result(const E& error) : storage_(error) {}
    Result(E&& error) : storage_(std::move(error)) {}

    /// Returns true if the result contains a value.
    explicit operator bool() const {
        return std::holds_alternative<T>(storage_);
    }

    bool has_value() const { return std::holds_alternative<T>(storage_); }
    bool has_error() const { return std::holds_alternative<E>(storage_); }

    /// Access the value. Throws if the result is an error.
    T& value() {
        if (has_error())
            throw std::runtime_error("Result contains error: " + error().message);
        return std::get<T>(storage_);
    }

    const T& value() const {
        if (has_error())
            throw std::runtime_error("Result contains error: " + error().message);
        return std::get<T>(storage_);
    }

    T& operator*() { return value(); }
    const T& operator*() const { return value(); }
    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }

    /// Access the error. Throws if the result contains a value.
    E& error() {
        if (has_value())
            throw std::runtime_error("Result contains a value, not an error");
        return std::get<E>(storage_);
    }

    const E& error() const {
        if (has_value())
            throw std::runtime_error("Result contains a value, not an error");
        return std::get<E>(storage_);
    }

    /// Returns the value or a default.
    T value_or(T default_val) const {
        return has_value() ? std::get<T>(storage_) : std::move(default_val);
    }

    /// Monadic map: transforms the value if present.
    template <typename Fn>
    auto map(Fn&& fn) const -> Result<decltype(fn(std::declval<T>())), E> {
        if (has_value())
            return fn(std::get<T>(storage_));
        return std::get<E>(storage_);
    }

private:
    std::variant<T, E> storage_;
};

/// Helper to create an error result.
inline Error make_error(std::string msg, int code = 0) {
    return Error{std::move(msg), code};
}

} // namespace bypasscore
