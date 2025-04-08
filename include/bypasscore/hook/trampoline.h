#pragma once

#include "../binary/disasm.h"
#include "../memory/protection.h"
#include "../util/result.h"
#include <cstdint>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bypasscore {
namespace hook {

/**
 * @brief Trampoline: a small code stub that preserves original instructions
 *        displaced by a detour, then jumps back to the remainder.
 *
 * x86:  overwrites 5 bytes (E9 rel32 JMP)
 * x64:  overwrites 14 bytes (FF 25 00000000 + abs64)
 */
class Trampoline {
public:
    struct Info {
        uint8_t* trampoline_addr = nullptr;
        size_t   trampoline_size = 0;
        size_t   stolen_bytes    = 0;
        std::vector<uint8_t> original;
    };

    static Result<Info> create(void* target, bool is_64bit = true) {
        if (!target) return make_error("Null target address");

        const uint8_t* code = static_cast<const uint8_t*>(target);
        binary::LengthDisasm disasm(
            is_64bit ? binary::LengthDisasm::Mode::X64
                     : binary::LengthDisasm::Mode::X86);

        size_t min_overwrite = is_64bit ? 14 : 5;

        // For very short functions (< min_overwrite bytes), try to use
        // a relative JMP (5 bytes) on x64 if the detour is within range
        size_t func_size = 0;
        for (size_t off = 0; off < 64; ++off) {
            size_t len = disasm.length(code + off);
            if (len == 0) break;
            off += len - 1;
            func_size = off + 1;
            // Check for RET (C3) or INT3 (CC) as function end
            if (code[off] == 0xC3 || code[off] == 0xCC) break;
        }
        if (is_64bit && func_size > 0 && func_size < 14 && func_size >= 5) {
            // Function is too short for 14-byte jmp, try 5-byte rel32
            min_overwrite = 5;
        }
        size_t stolen = disasm.calc_overwrite_size(code, min_overwrite);
        if (stolen == 0)
            return make_error("Failed to disassemble target instructions");

        size_t tramp_size = stolen + (is_64bit ? 14 : 5);

#ifdef _WIN32
        uint8_t* tramp = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, tramp_size,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!tramp) return make_error("Failed to allocate trampoline memory");
#else
        uint8_t* tramp = static_cast<uint8_t*>(aligned_alloc(16, tramp_size));
        if (!tramp) return make_error("Failed to allocate trampoline memory");
#endif

        Info info;
        info.trampoline_addr = tramp;
        info.trampoline_size = tramp_size;
        info.stolen_bytes    = stolen;
        info.original.assign(code, code + stolen);

        std::memcpy(tramp, code, stolen);

        uintptr_t jump_target = reinterpret_cast<uintptr_t>(code) + stolen;

        if (is_64bit) {
            // FF 25 00000000 [abs64]
            tramp[stolen + 0] = 0xFF;
            tramp[stolen + 1] = 0x25;
            tramp[stolen + 2] = 0x00;
            tramp[stolen + 3] = 0x00;
            tramp[stolen + 4] = 0x00;
            tramp[stolen + 5] = 0x00;
            std::memcpy(&tramp[stolen + 6], &jump_target, 8);
        } else {
            tramp[stolen] = 0xE9;
            int32_t rel = static_cast<int32_t>(
                jump_target - (reinterpret_cast<uintptr_t>(&tramp[stolen]) + 5));
            std::memcpy(&tramp[stolen + 1], &rel, 4);
        }

        return info;
    }


    /**
     * @brief Build an ARM64 trampoline using LDR + BR sequence.
     *
     * ARM64 hook: overwrites 16 bytes
     *   LDR X16, [PC, #8]   ; 58000050
     *   BR  X16              ; D61F0200
     *   <8 byte abs addr>
     */
    static Result<Info> create_arm64(void* target) {
        if (!target) return make_error("Null target");

        // ARM64 instructions are fixed 4 bytes, so we need at least 16 bytes
        // (4 instructions) to safely relocate
        constexpr size_t min_overwrite = 16;
        constexpr size_t tramp_size = 32; // Generous

#ifdef _WIN32
        uint8_t* tramp = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, tramp_size,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!tramp) return make_error("VirtualAlloc failed for ARM64 trampoline");
#else
        uint8_t* tramp = static_cast<uint8_t*>(aligned_alloc(16, tramp_size));
        if (!tramp) return make_error("Alloc failed");
#endif

        Info info;
        info.trampoline_addr = tramp;
        info.trampoline_size = tramp_size;
        info.stolen_bytes    = min_overwrite;
        info.original.assign(static_cast<uint8_t*>(target),
                             static_cast<uint8_t*>(target) + min_overwrite);

        // Copy original instructions
        std::memcpy(tramp, target, min_overwrite);

        // Append: LDR X16, [PC, #8]; BR X16; <addr>
        size_t off = min_overwrite;
        uint32_t ldr_x16 = 0x58000050;  // LDR X16, [PC+8]
        uint32_t br_x16  = 0xD61F0200;  // BR X16
        std::memcpy(&tramp[off], &ldr_x16, 4); off += 4;
        std::memcpy(&tramp[off], &br_x16, 4);  off += 4;
        uintptr_t ret_addr = reinterpret_cast<uintptr_t>(target) + min_overwrite;
        std::memcpy(&tramp[off], &ret_addr, 8);

        return info;
    }

    static void destroy(Info& info) {
        if (info.trampoline_addr) {
#ifdef _WIN32
            VirtualFree(info.trampoline_addr, 0, MEM_RELEASE);
#else
            free(info.trampoline_addr);
#endif
            info.trampoline_addr = nullptr;
        }
    }

    static Result<bool> install_jump(void* target, void* hook_fn,
                                     size_t stolen_bytes, bool is_64bit) {
        uint8_t* dst = static_cast<uint8_t*>(target);

        memory::ProtectionGuard guard(dst, stolen_bytes,
                                      memory::RegionAccess::ReadWrite);
        if (!guard) return make_error("Failed to change target protection");

        if (is_64bit) {
            dst[0] = 0xFF; dst[1] = 0x25;
            dst[2] = dst[3] = dst[4] = dst[5] = 0x00;
            uintptr_t addr = reinterpret_cast<uintptr_t>(hook_fn);
            std::memcpy(&dst[6], &addr, 8);
            for (size_t i = 14; i < stolen_bytes; ++i) dst[i] = 0x90;
        } else {
            dst[0] = 0xE9;
            int32_t rel = static_cast<int32_t>(
                reinterpret_cast<uintptr_t>(hook_fn) -
                (reinterpret_cast<uintptr_t>(dst) + 5));
            std::memcpy(&dst[1], &rel, 4);
            for (size_t i = 5; i < stolen_bytes; ++i) dst[i] = 0x90;
        }

        return true;
    }
};

} // namespace hook
} // namespace bypasscore
