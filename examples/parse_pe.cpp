/**
 * @file parse_pe.cpp
 * @brief Example: Parse a PE file and display its headers.
 */

#include "bypasscore/binary/pe.h"
#include <cstdio>
#include <fstream>
#include <vector>

int main(int argc, char* argv[]) {
    printf("BypassCore SDK - PE Parser Example\n");
    printf("===================================\n\n");

    if (argc < 2) {
        printf("Usage: %s <pe_file>\n", argv[0]);
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) {
        printf("Failed to open: %s\n", argv[1]);
        return 1;
    }

    size_t size = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);

    auto result = bypasscore::binary::PeImage::parse(data.data(), data.size());
    if (!result) {
        printf("PE parse error: %s\n", result.error().message.c_str());
        return 1;
    }

    auto& pe = *result;
    printf("File: %s\n", argv[1]);
    printf("Format: %s\n", pe.is_64bit() ? "PE32+ (64-bit)" : "PE32 (32-bit)");
    printf("Machine: 0x%04X\n", static_cast<uint16_t>(pe.machine()));
    printf("Image Base: 0x%llX\n", (unsigned long long)pe.image_base());
    printf("Entry Point RVA: 0x%08X\n", pe.entry_point_rva());
    printf("\nSections:\n");
    printf("  %-8s  %-10s  %-10s  %-10s  Flags\n",
           "Name", "VirtAddr", "VirtSize", "RawSize");

    for (const auto& sec : pe.sections()) {
        printf("  %-8s  0x%08X  0x%08X  0x%08X  %s%s%s\n",
               sec.name.c_str(), sec.virtual_address,
               sec.virtual_size, sec.raw_size,
               sec.is_readable() ? "R" : "-",
               sec.is_writable() ? "W" : "-",
               sec.is_executable() ? "X" : "-");
    }

    auto imports = pe.parse_imports();
    printf("\nImports: %zu entries\n", imports.size());
    std::string last_dll;
    for (const auto& imp : imports) {
        if (imp.dll_name != last_dll) {
            printf("  %s:\n", imp.dll_name.c_str());
            last_dll = imp.dll_name;
        }
        if (imp.by_ordinal)
            printf("    #%u\n", imp.ordinal);
        else
            printf("    %s\n", imp.function_name.c_str());
    }

    auto exports = pe.parse_exports();
    printf("\nExports: %zu entries\n", exports.size());
    for (const auto& exp : exports) {
        if (!exp.name.empty())
            printf("  [%u] %s (RVA: 0x%08X)%s\n",
                   exp.ordinal, exp.name.c_str(), exp.rva,
                   exp.forwarded ? " [forwarded]" : "");
    }

    return 0;
}
