/**
 * @file bc_dump.cpp
 * @brief PE dump utility - displays detailed PE header information.
 */

#include "bypasscore/binary/pe.h"
#include <cstdio>
#include <fstream>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: bc_dump <pe_file>\n");
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) { fprintf(stderr, "Cannot open: %s\n", argv[1]); return 1; }

    size_t size = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);

    auto pe = bypasscore::binary::PeImage::parse(data.data(), data.size());
    if (!pe) { fprintf(stderr, "Parse error: %s\n", pe.error().message.c_str()); return 1; }

    printf("=== PE Dump: %s ===\n\n", argv[1]);
    printf("Format:      %s\n", pe->is_64bit() ? "PE32+ (64-bit)" : "PE32 (32-bit)");
    printf("Machine:     0x%04X", static_cast<uint16_t>(pe->machine()));
    switch (pe->machine()) {
        case bypasscore::binary::MACHINE_I386:  printf(" (x86)"); break;
        case bypasscore::binary::MACHINE_AMD64: printf(" (x64)"); break;
        case bypasscore::binary::MACHINE_ARM64: printf(" (ARM64)"); break;
        default: break;
    }
    printf("\n");
    printf("Image Base:  0x%llX\n", (unsigned long long)pe->image_base());
    printf("Entry Point: 0x%08X\n\n", pe->entry_point_rva());

    printf("--- Sections ---\n");
    printf("%-8s  %-10s  %-10s  %-10s  %-10s  Prot\n",
           "Name", "VirtAddr", "VirtSize", "RawOff", "RawSize");
    for (const auto& s : pe->sections()) {
        printf("%-8s  0x%08X  0x%08X  0x%08X  0x%08X  %s%s%s\n",
               s.name.c_str(), s.virtual_address, s.virtual_size,
               s.raw_offset, s.raw_size,
               s.is_readable() ? "R" : "-",
               s.is_writable() ? "W" : "-",
               s.is_executable() ? "X" : "-");
    }

    auto imports = pe->parse_imports();
    if (!imports.empty()) {
        printf("\n--- Imports (%zu) ---\n", imports.size());
        std::string last;
        for (const auto& i : imports) {
            if (i.dll_name != last) { printf("\n  %s:\n", i.dll_name.c_str()); last = i.dll_name; }
            if (i.by_ordinal) printf("    #%u\n", i.ordinal);
            else printf("    %s (hint: %u)\n", i.function_name.c_str(), i.ordinal);
        }
    }

    auto exports = pe->parse_exports();
    if (!exports.empty()) {
        printf("\n--- Exports (%zu) ---\n", exports.size());
        for (const auto& e : exports) {
            if (!e.name.empty())
                printf("  [%u] %-40s RVA: 0x%08X%s\n", e.ordinal, e.name.c_str(),
                       e.rva, e.forwarded ? " (forwarded)" : "");
        }
    }

    return 0;
}
