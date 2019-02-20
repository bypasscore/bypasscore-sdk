#pragma once

#include "../util/result.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <optional>

namespace bypasscore {
namespace binary {

#pragma pack(push, 1)

struct DosHeader {
    uint16_t e_magic;
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr;
    uint16_t e_minalloc, e_maxalloc;
    uint16_t e_ss, e_sp, e_csum, e_ip, e_cs;
    uint16_t e_lfarlc, e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid, e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct CoffHeader {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

struct DataDirectory {
    uint32_t virtual_address;
    uint32_t size;
};

struct OptionalHeader32 {
    uint16_t magic;
    uint8_t  major_linker_version, minor_linker_version;
    uint32_t size_of_code, size_of_initialized_data, size_of_uninitialized_data;
    uint32_t address_of_entry_point, base_of_code, base_of_data;
    uint32_t image_base, section_alignment, file_alignment;
    uint16_t major_os_version, minor_os_version;
    uint16_t major_image_version, minor_image_version;
    uint16_t major_subsystem_version, minor_subsystem_version;
    uint32_t win32_version_value, size_of_image, size_of_headers, checksum;
    uint16_t subsystem, dll_characteristics;
    uint32_t size_of_stack_reserve, size_of_stack_commit;
    uint32_t size_of_heap_reserve, size_of_heap_commit;
    uint32_t loader_flags, number_of_rva_and_sizes;
    DataDirectory data_directories[16];
};

struct OptionalHeader64 {
    uint16_t magic;
    uint8_t  major_linker_version, minor_linker_version;
    uint32_t size_of_code, size_of_initialized_data, size_of_uninitialized_data;
    uint32_t address_of_entry_point, base_of_code;
    uint64_t image_base;
    uint32_t section_alignment, file_alignment;
    uint16_t major_os_version, minor_os_version;
    uint16_t major_image_version, minor_image_version;
    uint16_t major_subsystem_version, minor_subsystem_version;
    uint32_t win32_version_value, size_of_image, size_of_headers, checksum;
    uint16_t subsystem, dll_characteristics;
    uint64_t size_of_stack_reserve, size_of_stack_commit;
    uint64_t size_of_heap_reserve, size_of_heap_commit;
    uint32_t loader_flags, number_of_rva_and_sizes;
    DataDirectory data_directories[16];
};

struct SectionHeader {
    char     name[8];
    uint32_t virtual_size, virtual_address;
    uint32_t size_of_raw_data, pointer_to_raw_data;
    uint32_t pointer_to_relocations, pointer_to_line_numbers;
    uint16_t number_of_relocations, number_of_line_numbers;
    uint32_t characteristics;
};

#pragma pack(pop)

enum DataDirectoryIndex : uint32_t {
    DIR_EXPORT = 0, DIR_IMPORT = 1, DIR_RESOURCE = 2,
    DIR_EXCEPTION = 3, DIR_SECURITY = 4, DIR_BASERELOC = 5,
    DIR_DEBUG = 6, DIR_TLS = 9, DIR_LOAD_CONFIG = 10,
    DIR_IAT = 12, DIR_DELAY_IMPORT = 13, DIR_CLR_RUNTIME = 14
};

enum MachineType : uint16_t {
    MACHINE_UNKNOWN = 0x0,
    MACHINE_I386    = 0x14C,
    MACHINE_AMD64   = 0x8664,
    MACHINE_ARM64   = 0xAA64
};

struct Section {
    std::string name;
    uint32_t virtual_address = 0, virtual_size = 0;
    uint32_t raw_offset = 0, raw_size = 0;
    uint32_t characteristics = 0;
    bool is_executable() const { return (characteristics & 0x20000000) != 0; }
    bool is_readable()   const { return (characteristics & 0x40000000) != 0; }
    bool is_writable()   const { return (characteristics & 0x80000000) != 0; }
    bool contains_code() const { return (characteristics & 0x00000020) != 0; }
};

class PeImage {
public:
    PeImage() = default;

    static Result<PeImage> parse(const uint8_t* data, size_t size);

    bool is_64bit() const { return is_64bit_; }
    MachineType machine() const { return machine_; }
    uint32_t entry_point_rva() const { return entry_point_; }
    uint64_t image_base() const { return image_base_; }
    const std::vector<Section>& sections() const { return sections_; }

    std::optional<uint32_t> rva_to_offset(uint32_t rva) const;
    DataDirectory get_data_directory(DataDirectoryIndex index) const;
    const Section* find_section(const std::string& name) const;
    const uint8_t* ptr_from_rva(uint32_t rva) const;


    // --- Import/Export types ---

    struct ImportEntry {
        std::string dll_name;
        std::string function_name;
        uint16_t    ordinal     = 0;
        bool        by_ordinal  = false;
        uintptr_t   iat_address = 0;
    };

    struct ExportEntry {
        std::string name;
        uint32_t    ordinal = 0;
        uint32_t    rva     = 0;
        bool        forwarded = false;
        std::string forwarder;
    };

    std::vector<ImportEntry> parse_imports() const;
    std::vector<ExportEntry> parse_exports() const;

private:
    const uint8_t* raw_data_ = nullptr;
    size_t raw_size_ = 0;
    DosHeader dos_ = {};
    CoffHeader coff_ = {};
    OptionalHeader32 opt32_ = {};
    OptionalHeader64 opt64_ = {};
    bool is_64bit_ = false;
    MachineType machine_ = MACHINE_UNKNOWN;
    uint32_t entry_point_ = 0;
    uint64_t image_base_ = 0;
    uint32_t num_data_dirs_ = 0;
    std::vector<Section> sections_;
};

} // namespace binary
} // namespace bypasscore
