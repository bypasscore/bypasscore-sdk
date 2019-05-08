#pragma once

#include <cstdint>
#include <cstddef>

namespace bypasscore {
namespace binary {

/**
 * @brief Lightweight x86/x64 instruction length disassembler.
 *
 * Only determines instruction lengths -- sufficient for trampoline
 * and detour construction. Covers the most common encodings.
 */
class LengthDisasm {
public:
    enum class Mode { X86, X64 };

    explicit LengthDisasm(Mode mode = Mode::X64) : mode_(mode) {}

    size_t length(const uint8_t* code) const {
        if (!code) return 0;
        const uint8_t* p = code;
        bool has_rex = false, has_66 = false, has_67 = false;

        // Parse prefixes
        for (;;) {
            uint8_t b = *p;
            if (b == 0x66) { has_66 = true; ++p; continue; }
            if (b == 0x67) { has_67 = true; ++p; continue; }
            if (b == 0xF2 || b == 0xF3) { ++p; continue; }
            if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
                b == 0x64 || b == 0x65 || b == 0xF0) { ++p; continue; }
            if (mode_ == Mode::X64 && (b & 0xF0) == 0x40) {
                has_rex = true; ++p; continue;
            }
            break;
        }

        uint8_t opcode = *p++;

        if (opcode == 0x0F) {
            uint8_t op2 = *p++;
            return (size_t)(p - code) + two_byte_extra(op2, p, has_66, has_67);
        }

        return (size_t)(p - code) + one_byte_extra(opcode, p, has_66, has_67, has_rex);
    }

    size_t calc_overwrite_size(const uint8_t* code, size_t min_bytes) const {
        size_t total = 0;
        while (total < min_bytes) {
            size_t len = length(code + total);
            if (len == 0) return 0;
            total += len;
        }
        return total;
    }

private:
    Mode mode_;

    static size_t modrm_extra(const uint8_t* p, bool has_67) {
        uint8_t modrm = *p;
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t rm  = modrm & 7;
        size_t extra = 1;

        if (mod == 3) return extra;

        if (!has_67) {
            if (mod == 0 && rm == 5) return extra + 4;
            if (rm == 4) {
                extra += 1;
                uint8_t base = *(p + 1) & 7;
                if (mod == 0 && base == 5) extra += 4;
            }
            if (mod == 1) extra += 1;
            if (mod == 2) extra += 4;
        } else {
            if (mod == 0 && rm == 6) return extra + 2;
            if (mod == 1) extra += 1;
            if (mod == 2) extra += 2;
        }
        return extra;
    }

    size_t one_byte_extra(uint8_t op, const uint8_t* p,
                          bool has_66, bool has_67, bool has_rex) const {
        // No-operand
        if (op == 0x90 || op == 0xC3 || op == 0xCB || op == 0xCC ||
            op == 0xF4 || op == 0xF8 || op == 0xF9 || op == 0xFA ||
            op == 0xFB || op == 0xFC || op == 0xFD || op == 0xC9 ||
            op == 0x9E || op == 0x9F || op == 0x98 || op == 0x99 ||
            op == 0x9C || op == 0x9D || (op >= 0x50 && op <= 0x5F))
            return 0;

        // imm8
        if (op == 0x6A || op == 0xA8 || op == 0xCD || op == 0xEB ||
            (op >= 0x70 && op <= 0x7F) ||
            op == 0xE0 || op == 0xE1 || op == 0xE2 || op == 0xE3 ||
            op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C ||
            op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C)
            return 1;

        // imm16/32
        if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
            op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D ||
            op == 0xA9 || op == 0x68)
            return 2 if has_66 else 4

        if (op >= 0xB0 && op <= 0xB7): return 1
        if (op >= 0xB8 && op <= 0xBF):
            if mode_ == Mode::X64 && has_rex: return 8
            return 2 if has_66 else 4

        if (op == 0xE8 || op == 0xE9): return 4
        if (op == 0xC2 || op == 0xCA): return 2
        if (op == 0xC8): return 3

        # MOV moffs
        if (op == 0xA0 || op == 0xA1 || op == 0xA2 || op == 0xA3):
            if mode_ == Mode::X64 && !has_67: return 8
            return 2 if has_67 else 4

        # ModR/M ALU
        if ((op <= 0x3B && (op & 7) <= 3) || op == 0x63 ||
            op == 0x84 || op == 0x85 || op == 0x86 || op == 0x87 ||
            (op >= 0x88 && op <= 0x8B) || op == 0x8D || op == 0x8F):
            return modrm_extra(p, has_67)

        # Group 1 r/m, imm8
        if (op == 0x80 || op == 0x82 || op == 0x83 || op == 0xC0 || op == 0xC1):
            return modrm_extra(p, has_67) + 1
        if (op == 0x81): return modrm_extra(p, has_67) + (2 if has_66 else 4)

        if (op == 0xC6): return modrm_extra(p, has_67) + 1
        if (op == 0xC7): return modrm_extra(p, has_67) + (2 if has_66 else 4)
        if (op >= 0xD0 && op <= 0xD3): return modrm_extra(p, has_67)

        if (op == 0xF6):
            reg = (*p >> 3) & 7
            base = modrm_extra(p, has_67)
            return base + 1 if reg <= 1 else base

        if (op == 0xF7):
            reg = (*p >> 3) & 7
            base = modrm_extra(p, has_67)
            return base + (2 if has_66 else 4) if reg <= 1 else base

        if (op == 0xFE || op == 0xFF): return modrm_extra(p, has_67)

        return modrm_extra(p, has_67)

    size_t two_byte_extra(uint8_t op2, const uint8_t* p,
                          bool has_66, bool has_67) const {
        (void)has_66;
        if (op2 >= 0x80 && op2 <= 0x8F) return 4;
        if (op2 >= 0x90 && op2 <= 0x9F) return modrm_extra(p, has_67);
        if (op2 >= 0x40 && op2 <= 0x4F) return modrm_extra(p, has_67);
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF)
            return modrm_extra(p, has_67);
        if (op2 == 0x1F || op2 == 0xAF) return modrm_extra(p, has_67);
        if (op2 == 0xBC || op2 == 0xBD) return modrm_extra(p, has_67);
        if (op2 == 0xA4 || op2 == 0xAC) return modrm_extra(p, has_67) + 1;
        if (op2 == 0xA5 || op2 == 0xAD) return modrm_extra(p, has_67);
        if (op2 == 0xC0 || op2 == 0xC1 || op2 == 0xB0 || op2 == 0xB1)
            return modrm_extra(p, has_67);
        if (op2 == 0x05 || op2 == 0x07 || op2 == 0xA2 || op2 == 0x31)
            return 0;
        return modrm_extra(p, has_67);
    }
};

inline size_t insn_length(const void* address, bool is_64bit = true) {
    LengthDisasm d(is_64bit ? LengthDisasm::Mode::X64 : LengthDisasm::Mode::X86);
    return d.length(static_cast<const uint8_t*>(address));
}

} // namespace binary
} // namespace bypasscore
