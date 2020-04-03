#pragma once

#include "../memory/protection.h"
#include "../util/result.h"
#include "../util/logger.h"
#include <cstdint>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bypasscore {
namespace hook {

/**
 * @brief VMT (Virtual Method Table) hook via table-swap technique.
 */
class VmtHook {
public:
    VmtHook() = default;
    ~VmtHook() { unhook_all(); }
    VmtHook(const VmtHook&) = delete;
    VmtHook& operator=(const VmtHook&) = delete;

    Result<bool> initialize(void* object) {
        if (!object) return make_error("Null object pointer");
        object_ = object;
        original_vtable_ = *reinterpret_cast<uintptr_t**>(object);
        vtable_size_ = count_vtable_entries(original_vtable_);
        if (vtable_size_ == 0) return make_error("Empty vtable");

        shadow_.resize(vtable_size_);
        std::memcpy(shadow_.data(), original_vtable_, vtable_size_ * sizeof(uintptr_t));

        memory::ProtectionGuard guard(object_, sizeof(uintptr_t),
                                      memory::RegionAccess::ReadWrite);
        if (!guard) return make_error("Failed to change object protection");
        *reinterpret_cast<uintptr_t**>(object_) = shadow_.data();
        init_ = true;
        return true;
    }

    Result<void*> hook(size_t index, void* detour) {
        if (!init_) return make_error("Not initialized");
        if (index >= vtable_size_) return make_error("Index out of bounds");
        void* orig = reinterpret_cast<void*>(shadow_[index]);
        shadow_[index] = reinterpret_cast<uintptr_t>(detour);
        return orig;
    }

    Result<bool> unhook(size_t index) {
        if (!init_ || index >= vtable_size_) return make_error("Invalid");
        shadow_[index] = reinterpret_cast<uintptr_t>(original_vtable_[index]);
        return true;
    }

    void unhook_all() {
        if (!init_ || !object_) return;
        memory::ProtectionGuard guard(object_, sizeof(uintptr_t),
                                      memory::RegionAccess::ReadWrite);
        if (guard) *reinterpret_cast<uintptr_t**>(object_) = original_vtable_;
        shadow_.clear(); init_ = false;
    }

    void* get_original(size_t index) const {
        if (!init_ || index >= vtable_size_) return nullptr;
        return reinterpret_cast<void*>(original_vtable_[index]);
    }

    size_t vtable_size() const { return vtable_size_; }

private:
    static size_t count_vtable_entries(uintptr_t* vt) {
        size_t count = 0;
#ifdef _WIN32
        for (size_t i = 0; i < 1024; ++i) {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(reinterpret_cast<void*>(vt[i]), &mbi, sizeof(mbi))) break;
            if (mbi.State != MEM_COMMIT) break;
            if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                  PAGE_EXECUTE_READWRITE))) break;
            ++count;
        }
#else
        for (size_t i = 0; i < 1024 && vt[i]; ++i) ++count;
#endif
        return count;
    }

    void*      object_           = nullptr;
    uintptr_t* original_vtable_  = nullptr;
    size_t     vtable_size_      = 0;
    bool       init_             = false;
    std::vector<uintptr_t> shadow_;
};

} // namespace hook
} // namespace bypasscore
