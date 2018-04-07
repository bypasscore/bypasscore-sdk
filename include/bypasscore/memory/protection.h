#pragma once

#include "region.h"
#include "../util/result.h"
#include "../util/scope_guard.h"
#include <cstdint>
#include <cstddef>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bypasscore {
namespace memory {

/**
 * @brief RAII-based page protection modifier.
 *
 * Changes the protection of a memory region and automatically
 * restores the original protection on destruction.
 *
 * Usage:
 *   {
 *       ProtectionGuard guard(address, size, RegionAccess::ReadWrite);
 *       if (guard) {
 *           memcpy(address, payload, size);
 *       }
 *   } // original protection restored here
 */
class ProtectionGuard {
public:
    ProtectionGuard(void* address, size_t size, RegionAccess new_access)
        : address_(address), size_(size), valid_(false), old_protect_(0) {
#ifdef _WIN32
        DWORD desired = to_win32_protect(new_access);
        valid_ = VirtualProtect(address_, size_, desired, &old_protect_) != FALSE;
#endif
    }

    ~ProtectionGuard() {
        restore();
    }

    ProtectionGuard(ProtectionGuard&& other) noexcept
        : address_(other.address_), size_(other.size_),
          valid_(other.valid_), old_protect_(other.old_protect_) {
        other.valid_ = false;
    }

    ProtectionGuard(const ProtectionGuard&) = delete;
    ProtectionGuard& operator=(const ProtectionGuard&) = delete;

    explicit operator bool() const { return valid_; }

    bool restore() {
        if (!valid_) return false;
#ifdef _WIN32
        DWORD dummy;
        BOOL ok = VirtualProtect(address_, size_, old_protect_, &dummy);
        valid_ = false;
        return ok != FALSE;
#else
        valid_ = false;
        return false;
#endif
    }

private:
    void* address_;
    size_t size_;
    bool valid_;
#ifdef _WIN32
    DWORD old_protect_;
#else
    int old_protect_;
#endif
};

/**
 * @brief Change memory protection for the given region.
 *
 * @return The old protection flags on success.
 */
inline Result<RegionAccess> set_protection(void* address, size_t size,
                                           RegionAccess new_access) {
#ifdef _WIN32
    DWORD old_protect = 0;
    DWORD desired = to_win32_protect(new_access);
    if (!VirtualProtect(address, size, desired, &old_protect)) {
        return make_error("VirtualProtect failed", static_cast<int>(GetLastError()));
    }
    return from_win32_protect(old_protect);
#else
    (void)address; (void)size; (void)new_access;
    return make_error("Not implemented on this platform");
#endif
}

/**
 * @brief Query the protection of a single address.
 */
inline Result<RegionAccess> query_protection(const void* address) {
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
        return make_error("VirtualQuery failed", static_cast<int>(GetLastError()));
    }
    return from_win32_protect(mbi.Protect);
#else
    (void)address;
    return make_error("Not implemented on this platform");
#endif
}

} // namespace memory
} // namespace bypasscore
