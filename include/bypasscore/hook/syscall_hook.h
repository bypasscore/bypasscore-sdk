#pragma once

#include "../util/result.h"
#include "../memory/protection.h"
#include "../platform/ntapi.h"
#include <cstdint>
#include <cstring>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bypasscore {
namespace hook {

/**
 * @brief Syscall hooking via ntdll stub patching.
 *
 * On Windows, user-mode syscalls go through ntdll stubs that contain:
 *   mov r10, rcx
 *   mov eax, <syscall_number>
 *   syscall
 *   ret
 *
 * This class patches the syscall stub to redirect to a user hook.
 */
class SyscallHook {
public:
    SyscallHook() = default;
    ~SyscallHook() { restore_all(); }

    /**
     * @brief Extract the syscall number from an ntdll stub.
     */
    static Result<uint32_t> get_syscall_number(void* ntdll_func) {
#ifdef _WIN32
        auto* code = static_cast<const uint8_t*>(ntdll_func);

        // x64 ntdll stub pattern:
        // 4C 8B D1          mov r10, rcx
        // B8 xx xx 00 00    mov eax, syscall_number
        if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 &&
            code[3] == 0xB8) {
            uint32_t num = *reinterpret_cast<const uint32_t*>(code + 4);
            return num;
        }

        // Alternative pattern (hooked by AV):
        // E9 xx xx xx xx    jmp <somewhere>
        if (code[0] == 0xE9) {
            return make_error("Stub already hooked (JMP detected)");
        }

        return make_error("Unknown syscall stub format");
#else
        return make_error("Windows-only");
#endif
    }

    /**
     * @brief Hook a syscall by patching the ntdll stub.
     */
    Result<bool> hook(const char* function_name, void* detour, void** original) {
#ifdef _WIN32
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return make_error("ntdll.dll not found");

        void* target = reinterpret_cast<void*>(
            GetProcAddress(ntdll, function_name));
        if (!target) return make_error("Function not found in ntdll");

        auto* code = static_cast<uint8_t*>(target);

        // Save original bytes (enough for the stub)
        constexpr size_t STUB_SIZE = 16;
        std::vector<uint8_t> orig(STUB_SIZE);
        std::memcpy(orig.data(), code, STUB_SIZE);

        if (original) *original = nullptr; // Will be set after patching

        // Write a JMP to our detour
        memory::ProtectionGuard guard(code, STUB_SIZE,
                                      memory::RegionAccess::ReadWrite);
        if (!guard) return make_error("Failed to change protection");

        // Use absolute jump: FF 25 00000000 [abs64]
        code[0] = 0xFF;
        code[1] = 0x25;
        code[2] = code[3] = code[4] = code[5] = 0x00;
        uintptr_t addr = reinterpret_cast<uintptr_t>(detour);
        std::memcpy(&code[6], &addr, 8);

        HookInfo info;
        info.target = target;
        info.original_bytes = std::move(orig);

        // The original pointer would need a trampoline for proper forwarding
        // For syscall hooks, the caller typically reconstructs the syscall manually
        hooks_[function_name] = std::move(info);

        return true;
#else
        return make_error("Windows-only");
#endif
    }

    /**
     * @brief Restore a single hooked syscall.
     */
    Result<bool> restore(const char* function_name) {
#ifdef _WIN32
        auto it = hooks_.find(function_name);
        if (it == hooks_.end()) return make_error("Hook not found");

        auto& info = it->second;
        auto* code = static_cast<uint8_t*>(info.target);

        memory::ProtectionGuard guard(code, info.original_bytes.size(),
                                      memory::RegionAccess::ReadWrite);
        if (!guard) return make_error("Failed to change protection");

        std::memcpy(code, info.original_bytes.data(), info.original_bytes.size());
        hooks_.erase(it);
        return true;
#else
        return make_error("Windows-only");
#endif
    }

    void restore_all() {
        std::vector<std::string> names;
        for (auto& [name, _] : hooks_) names.push_back(name);
        for (auto& name : names) restore(name.c_str());
    }

private:
    struct HookInfo {
        void* target = nullptr;
        std::vector<uint8_t> original_bytes;
    };
    std::unordered_map<std::string, HookInfo> hooks_;
};

} // namespace hook
} // namespace bypasscore
