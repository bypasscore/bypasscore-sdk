#pragma once

#include "pe.h"
#include "../util/result.h"
#include <cstdint>
#include <vector>

namespace bypasscore {
namespace binary {

enum RelocType : uint8_t {
    RELOC_ABSOLUTE       = 0,  // No relocation
    RELOC_HIGH           = 1,  // High 16 bits
    RELOC_LOW            = 2,  // Low 16 bits
    RELOC_HIGHLOW        = 3,  // Full 32-bit
    RELOC_HIGHADJ        = 4,  // High 16 bits + adjust
    RELOC_DIR64          = 10  // Full 64-bit
};

struct RelocationEntry {
    uint32_t  rva  = 0;
    RelocType type = RELOC_ABSOLUTE;
};

/**
 * @brief Parse base relocation table from a PE image.
 */
inline std::vector<RelocationEntry> parse_relocations(const PeImage& pe) {
    std::vector<RelocationEntry> entries;
    auto dir = pe.get_data_directory(DIR_BASERELOC);
    if (dir.virtual_address == 0 || dir.size == 0) return entries;

    const uint8_t* base = pe.ptr_from_rva(dir.virtual_address);
    if (!base) return entries;

    size_t offset = 0;
    while (offset + 8 <= dir.size) {
        uint32_t page_rva   = *reinterpret_cast<const uint32_t*>(base + offset);
        uint32_t block_size = *reinterpret_cast<const uint32_t*>(base + offset + 4);

        if (block_size == 0 || block_size < 8) break;

        size_t entry_count = (block_size - 8) / 2;
        const uint16_t* relocs = reinterpret_cast<const uint16_t*>(base + offset + 8);

        for (size_t i = 0; i < entry_count; ++i) {
            uint16_t entry = relocs[i];
            uint8_t  type  = entry >> 12;
            uint16_t off   = entry & 0xFFF;

            if (type != RELOC_ABSOLUTE) {
                RelocationEntry re;
                re.rva  = page_rva + off;
                re.type = static_cast<RelocType>(type);
                entries.push_back(re);
            }
        }
        offset += block_size;
    }
    return entries;
}

/**
 * @brief Apply relocations to rebase an image to a new base address.
 */
inline Result<bool> apply_relocations(uint8_t* image, size_t image_size,
                                       const PeImage& pe, uint64_t new_base) {
    int64_t delta = static_cast<int64_t>(new_base) -
                    static_cast<int64_t>(pe.image_base());

    if (delta == 0) return true; // No relocation needed

    auto entries = parse_relocations(pe);
    for (const auto& entry : entries) {
        auto offset = pe.rva_to_offset(entry.rva);
        if (!offset || *offset + 8 > image_size) continue;

        uint8_t* target = image + *offset;

        switch (entry.type) {
            case RELOC_HIGHLOW: {
                uint32_t val;
                std::memcpy(&val, target, 4);
                val += static_cast<uint32_t>(delta);
                std::memcpy(target, &val, 4);
                break;
            }
            case RELOC_DIR64: {
                uint64_t val;
                std::memcpy(&val, target, 8);
                val += static_cast<uint64_t>(delta);
                std::memcpy(target, &val, 8);
                break;
            }
            case RELOC_HIGH: {
                uint16_t val;
                std::memcpy(&val, target, 2);
                val += static_cast<uint16_t>(delta >> 16);
                std::memcpy(target, &val, 2);
                break;
            }
            case RELOC_LOW: {
                uint16_t val;
                std::memcpy(&val, target, 2);
                val += static_cast<uint16_t>(delta & 0xFFFF);
                std::memcpy(target, &val, 2);
                break;
            }
            default:
                break;
        }
    }
    return true;
}

} // namespace binary
} // namespace bypasscore
