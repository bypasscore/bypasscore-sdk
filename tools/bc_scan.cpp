/**
 * @file bc_scan.cpp
 * @brief Standalone AOB pattern scanner for files.
 */

#include "bypasscore/memory/scanner.h"
#include <cstdio>
#include <fstream>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: bc_scan <file> <pattern>\n");
        fprintf(stderr, "  Pattern: IDA-style hex, e.g. \"48 8B 05 ?? ?? ?? ??\"\n");
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) { fprintf(stderr, "Cannot open: %s\n", argv[1]); return 1; }

    size_t size = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);

    auto pat = bypasscore::memory::parse_pattern(argv[2]);
    if (!pat) {
        fprintf(stderr, "Invalid pattern: %s\n", pat.error().message.c_str());
        return 1;
    }

    printf("Scanning %s (%zu bytes) for: %s\n\n", argv[1], size, argv[2]);

    auto offsets = bypasscore::memory::scan_buffer_all(data.data(), data.size(), *pat);

    if (offsets.empty()) {
        printf("No matches found.\n");
    } else {
        printf("Found %zu match(es):\n", offsets.size());
        for (size_t off : offsets) {
            printf("  Offset: 0x%08zX  |  ", off);
            for (size_t j = 0; j < (*pat).size() && off + j < size; ++j)
                printf("%02X ", data[off + j]);
            printf("\n");
        }
    }

    return 0;
}
