#pragma once

#include <functional>
#include <utility>

namespace bypasscore {

/**
 * @brief RAII scope guard that executes a callable on destruction.
 *
 * Usage:
 *   auto guard = make_scope_guard([&]() { cleanup(); });
 *   // ... do work ...
 *   guard.dismiss(); // optional: prevent cleanup
 */
class ScopeGuard {
public:
    template <typename Fn>
    explicit ScopeGuard(Fn&& fn)
        : cleanup_(std::forward<Fn>(fn)), active_(true) {}

    ~ScopeGuard() {
        if (active_) {
            try {
                cleanup_();
            } catch (...) {
                // Never throw from destructors
            }
        }
    }

    ScopeGuard(ScopeGuard&& other) noexcept
        : cleanup_(std::move(other.cleanup_)), active_(other.active_) {
        other.dismiss();
    }

    ScopeGuard& operator=(ScopeGuard&&) = delete;
    ScopeGuard(const ScopeGuard&) = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;

    /// Prevent the guard from executing on destruction.
    void dismiss() noexcept { active_ = false; }

    /// Check if the guard is still active.
    bool is_active() const noexcept { return active_; }

private:
    std::function<void()> cleanup_;
    bool active_;
};

/// Factory function for creating scope guards with type deduction.
template <typename Fn>
ScopeGuard make_scope_guard(Fn&& fn) {
    return ScopeGuard(std::forward<Fn>(fn));
}

/**
 * @brief Macro for anonymous scope guards that execute at end of scope.
 *
 * Usage:
 *   BYPASSCORE_SCOPE_EXIT { cleanup(); };
 */
#define BYPASSCORE_CONCAT_IMPL(a, b) a##b
#define BYPASSCORE_CONCAT(a, b) BYPASSCORE_CONCAT_IMPL(a, b)
#define BYPASSCORE_SCOPE_EXIT \
    auto BYPASSCORE_CONCAT(_scope_guard_, __LINE__) = \
        ::bypasscore::detail::ScopeGuardHelper{} + [&]()

namespace detail {
    struct ScopeGuardHelper {
        template <typename Fn>
        ScopeGuard operator+(Fn&& fn) {
            return ScopeGuard(std::forward<Fn>(fn));
        }
    };
} // namespace detail

} // namespace bypasscore
