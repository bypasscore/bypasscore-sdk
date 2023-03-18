/**
 * @file scan_pattern.cpp
 * @brief Example: Scan a buffer for an AOB pattern.
 */

#include "bypasscore/memory/scanner.h"
#include <cstdio>
#include <vector>

int main() {
    printf("BypassCore SDK - Pattern Scanner Example\n");
    printf("=========================================\n\n");

    // Create a test buffer with known bytes
    std::vector<uint8_t> buffer = {
        0x55, 0x48, 0x89, 0xE5,                     // push rbp; mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20,                     // sub rsp, 0x20
        0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD,  // mov rax, [rip+0xDDCCBBAA]
        0x48, 0x85, 0xC0,                           // test rax, rax
        0x74, 0x0A,                                  // jz +10
        0xFF, 0xD0,                                  // call rax
        0x90, 0x90, 0x90,                            // nop nop nop
        0xC3                                          // ret
    };

    printf("Buffer size: %zu bytes\n\n", buffer.size());

    // Scan for "48 8B 05 ?? ?? ?? ?? 48 85 C0"
    const char* pattern = "48 8B 05 ?? ?? ?? ?? 48 85 C0";
    printf("Pattern: %s\n", pattern);

    auto parsed = bypasscore::memory::parse_pattern(pattern);
    if (!parsed) {
        printf("Failed to parse pattern: %s\n", parsed.error().message.c_str());
        return 1;
    }

    printf("Parsed %zu bytes\n", parsed->size());

    auto offset = bypasscore::memory::scan_buffer(
        buffer.data(), buffer.size(), *parsed);

    if (offset) {
        printf("Found at offset: 0x%zX\n", *offset);
    } else {
        printf("Pattern not found.\n");
    }

    // Scan for all NOPs
    auto nop_offsets = bypasscore::memory::scan_buffer_all(
        buffer.data(), buffer.size(),
        {{0x90, false}, {0x90, false}, {0x90, false}});

    printf("\nNOP sled locations: ");
    for (size_t off : nop_offsets) printf("0x%zX ", off);
    printf("\n");

    return 0;
}
