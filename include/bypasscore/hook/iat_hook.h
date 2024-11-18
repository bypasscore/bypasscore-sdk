#pragma once

#include "../binary/pe.h"
#include "../memory/protection.h"
#include "../util/result.h"
#include "../util/logger.h"
#include <cstdint>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bypasscore {
namespace hook {

/**
 * @brief IAT (Import Address Table) hook.
 *
 * Patches a function pointer in a module's IAT to redirect calls.
 */
class IatHook {
public:
    IatHook() = default;
    ~IatHook() { remove(); }
    IatHook(const IatHook&) = delete;
    IatHook& operator=(const IatHook&) = delete;

    Result<bool> install(void* module_base, const char* target_dll,
                         const char* target_func, void* detour, void** original) {
#ifdef _WIN32
        if (!module_base || !target_dll || !target_func || !detour)
            return make_error("Invalid parameters");

        auto* base_ptr = static_cast<const uint8_t*>(module_base);
        auto base_addr = reinterpret_cast<uintptr_t>(module_base);

        auto* dos = reinterpret_cast<const binary::DosHeader*>(base_ptr);
        if (dos->e_magic != 0x5A4D) return make_error("Invalid DOS header");

        uint32_t pe_off = static_cast<uint32_t>(dos->e_lfanew);
        auto* coff = reinterpret_cast<const binary::CoffHeader*>(base_ptr + pe_off + 4);
        const uint8_t* opt = base_ptr + pe_off + 4 + sizeof(binary::CoffHeader);
        uint16_t magic = *reinterpret_cast<const uint16_t*>(opt);
        bool is_64 = (magic == 0x20B);

        uint32_t import_rva;
        if (is_64) {
            auto* h = reinterpret_cast<const binary::OptionalHeader64*>(opt);
            import_rva = h->data_directories[binary::DIR_IMPORT].virtual_address;
        } else {
            auto* h = reinterpret_cast<const binary::OptionalHeader32*>(opt);
            import_rva = h->data_directories[binary::DIR_IMPORT].virtual_address;
        }
        if (import_rva == 0) return make_error("No import directory");

        auto* imp = base_ptr + import_rva;
        for (size_t off = 0; ; off += 20) {
            uint32_t name_rva = *reinterpret_cast<const uint32_t*>(imp + off + 12);
            uint32_t ft_rva   = *reinterpret_cast<const uint32_t*>(imp + off + 16);
            uint32_t oft_rva  = *reinterpret_cast<const uint32_t*>(imp + off);
            if (name_rva == 0) break;

            auto* dll = reinterpret_cast<const char*>(base_addr + name_rva);
            if (_stricmp(dll, target_dll) != 0) continue;

            uint32_t thunk_rva = (oft_rva != 0) ? oft_rva : ft_rva;
            size_t psz = is_64 ? 8 : 4;

            for (size_t i = 0; ; ++i) {
                auto* thunk = reinterpret_cast<const uint8_t*>(base_addr + thunk_rva + i * psz);
                auto* iat = reinterpret_cast<uintptr_t*>(base_addr + ft_rva + i * psz);

                uint64_t val = is_64
                    ? *reinterpret_cast<const uint64_t*>(thunk)
                    : *reinterpret_cast<const uint32_t*>(thunk);
                if (val == 0) break;

                uint64_t ord_flag = is_64 ? (1ULL << 63) : (1ULL << 31);
                if (val & ord_flag) continue;

                uint32_t hint_rva = static_cast<uint32_t>(val);
                auto* hint = reinterpret_cast<const uint8_t*>(base_addr + hint_rva);
                const char* fname = reinterpret_cast<const char*>(hint + 2);

                if (strcmp(fname, target_func) == 0) {
                    iat_slot_ = iat;
                    original_value_ = *iat;
                    if (original) *original = reinterpret_cast<void*>(original_value_);

                    memory::ProtectionGuard pg(iat, psz, memory::RegionAccess::ReadWrite);
                    if (!pg) return make_error("Failed to change IAT protection");
                    *iat = reinterpret_cast<uintptr_t>(detour);
                    installed_ = true;
                    return true;
                }
            }
        }
        return make_error("Function not found in IAT");
#else
        return make_error("IAT hooking is Windows-only");
#endif
    }

    Result<bool> remove() {
        if (!installed_) return true;
        if (!iat_slot_) return make_error("IAT slot is null (already freed?)");
#ifdef _WIN32
        memory::ProtectionGuard guard(iat_slot_, sizeof(uintptr_t),
                                      memory::RegionAccess::ReadWrite);
        if (!guard) return make_error("Failed to restore IAT protection");
        *iat_slot_ = original_value_;
        installed_ = false;
        return true;
#else
        return make_error("IAT hooking is Windows-only");
#endif
    }

    bool is_installed() const { return installed_; }

private:
    uintptr_t* iat_slot_       = nullptr;
    uintptr_t  original_value_ = 0;
    bool       installed_      = false;
};

} // namespace hook
} // namespace bypasscore
