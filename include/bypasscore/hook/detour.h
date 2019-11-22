#pragma once

#include "engine.h"
#include "trampoline.h"
#include "../util/result.h"
#include "../util/logger.h"
#include <cstring>

namespace bypasscore {
namespace hook {

/**
 * @brief Inline detour hook -- replaces the first bytes of a target function
 *        with a JMP to a user-supplied detour function.
 */
class DetourHook {
public:
    DetourHook() = default;
    ~DetourHook() { remove(); }
    DetourHook(const DetourHook&) = delete;
    DetourHook& operator=(const DetourHook&) = delete;

    template <typename T>
    Result<bool> install(void* target, void* detour, T* original) {
        return install_impl(target, detour, reinterpret_cast<void**>(original));
    }

    Result<bool> remove() {
        if (!installed_) return true;
        auto* dst = static_cast<uint8_t*>(target_);
        memory::ProtectionGuard guard(dst, trampoline_.stolen_bytes,
                                      memory::RegionAccess::ReadWrite);
        if (!guard) return make_error("Failed to restore protection");
        std::memcpy(dst, trampoline_.original.data(), trampoline_.stolen_bytes);
        Trampoline::destroy(trampoline_);
        installed_ = false;
        return true;
    }

    bool is_installed() const { return installed_; }

private:
    Result<bool> install_impl(void* target, void* detour, void** original) {
        if (installed_) return make_error("Hook already installed");
        if (!target || !detour) return make_error("Null target or detour");

#if defined(_M_X64) || defined(__x86_64__)
        constexpr bool is_64 = true;
#else
        constexpr bool is_64 = false;
#endif
        target_ = target;
        auto result = Trampoline::create(target, is_64);
        if (!result) return make_error("Trampoline creation failed");
        trampoline_ = *result;
        if (original) *original = trampoline_.trampoline_addr;

        auto jmp = Trampoline::install_jump(target, detour, trampoline_.stolen_bytes, is_64);
        if (!jmp) { Trampoline::destroy(trampoline_); return make_error("Jump install failed"); }

        installed_ = true;
        BC_DEBUG("Detour installed at %p -> %p", target, detour);
        return true;
    }

    void*            target_     = nullptr;
    Trampoline::Info trampoline_ = {};
    bool             installed_  = false;
};

} // namespace hook
} // namespace bypasscore
