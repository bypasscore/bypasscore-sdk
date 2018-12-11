#include "bypasscore/binary/pe.h"

namespace bypasscore {
namespace binary {

Result<PeImage> PeImage::parse(const uint8_t* data, size_t size) {
    if (!data || size < sizeof(DosHeader))
        return make_error("Buffer too small for DOS header");
    PeImage img;
    img.raw_data_ = data;
    img.raw_size_ = size;

    auto* dos = reinterpret_cast<const DosHeader*>(data);
    if (dos->e_magic != 0x5A4D) return make_error("Invalid DOS signature");
    img.dos_ = *dos;

    uint32_t pe_offset = static_cast<uint32_t>(dos->e_lfanew);
    if (pe_offset + 4 + sizeof(CoffHeader) > size)
        return make_error("PE header offset out of bounds");

    // PE\0\0 signature as little-endian uint32
    uint32_t pe_sig = 0x00004550u;
    if (*reinterpret_cast<const uint32_t*>(data + pe_offset) != pe_sig)
        return make_error("Invalid PE signature");

    auto* coff = reinterpret_cast<const CoffHeader*>(data + pe_offset + 4);
    img.coff_ = *coff;
    img.machine_ = static_cast<MachineType>(coff->machine);

    const uint8_t* opt_start = data + pe_offset + 4 + sizeof(CoffHeader);
    if (opt_start + 2 > data + size)
        return make_error("Optional header out of bounds");

    uint16_t magic = *reinterpret_cast<const uint16_t*>(opt_start);
    img.is_64bit_ = (magic == 0x20B);

    if (img.is_64bit_) {
        if (opt_start + sizeof(OptionalHeader64) > data + size)
            return make_error("PE32+ optional header out of bounds");
        img.opt64_ = *reinterpret_cast<const OptionalHeader64*>(opt_start);
        img.entry_point_   = img.opt64_.address_of_entry_point;
        img.image_base_    = img.opt64_.image_base;
        img.num_data_dirs_ = img.opt64_.number_of_rva_and_sizes;
    } else {
        if (opt_start + sizeof(OptionalHeader32) > data + size)
            return make_error("PE32 optional header out of bounds");
        img.opt32_ = *reinterpret_cast<const OptionalHeader32*>(opt_start);
        img.entry_point_   = img.opt32_.address_of_entry_point;
        img.image_base_    = img.opt32_.image_base;
        img.num_data_dirs_ = img.opt32_.number_of_rva_and_sizes;
    }

    const uint8_t* sec_start = data + pe_offset + 4 +
        sizeof(CoffHeader) + coff->size_of_optional_header;
    for (uint16_t i = 0; i < coff->number_of_sections; ++i) {
        if (sec_start + (i + 1) * sizeof(SectionHeader) > data + size) break;
        auto* sh = reinterpret_cast<const SectionHeader*>(
            sec_start + i * sizeof(SectionHeader));
        Section sec;
        sec.name = std::string(sh->name, strnlen(sh->name, 8));
        sec.virtual_address = sh->virtual_address;
        sec.virtual_size    = sh->virtual_size;
        sec.raw_offset      = sh->pointer_to_raw_data;
        sec.raw_size        = sh->size_of_raw_data;
        sec.characteristics = sh->characteristics;
        img.sections_.push_back(sec);
    }
    return img;
}

std::optional<uint32_t> PeImage::rva_to_offset(uint32_t rva) const {
    for (const auto& sec : sections_) {
        if (rva >= sec.virtual_address &&
            rva < sec.virtual_address + sec.virtual_size)
            return sec.raw_offset + (rva - sec.virtual_address);
    }
    return std::nullopt;
}

DataDirectory PeImage::get_data_directory(DataDirectoryIndex index) const {
    if (static_cast<uint32_t>(index) >= num_data_dirs_) return {0, 0};
    return is_64bit_ ? opt64_.data_directories[index]
                     : opt32_.data_directories[index];
}

const Section* PeImage::find_section(const std::string& name) const {
    for (const auto& sec : sections_)
        if (sec.name == name) return &sec;
    return nullptr;
}

const uint8_t* PeImage::ptr_from_rva(uint32_t rva) const {
    auto offset = rva_to_offset(rva);
    if (!offset || *offset >= raw_size_) return nullptr;
    return raw_data_ + *offset;
}

} // namespace binary
} // namespace bypasscore
