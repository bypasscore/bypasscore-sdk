#include "bypasscore/memory/scanner.h"
#include <cassert>
#include <cstdio>
#include <vector>

using namespace bypasscore::memory;

void test_parse_pattern_ida_style() {
    auto r = parse_pattern("48 8B 05 ?? ?? ?? ??");
    assert(r);
    assert(r->size() == 7);
    assert((*r)[0].value == 0x48 && !(*r)[0].wildcard);
    assert((*r)[3].wildcard);
    printf("  PASS: parse_pattern (IDA style)\n");
}

void test_parse_pattern_single_wildcard() {
    auto r = parse_pattern("FF 25 ? ? ? ?");
    assert(r && r->size() == 6);
    assert((*r)[2].wildcard);
    printf("  PASS: parse_pattern (single ? wildcard)\n");
}

void test_scan_buffer_found() {
    uint8_t data[] = {0x00, 0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0x90};
    auto pat = parse_pattern("48 8B 05 ?? ?? ?? ??");
    assert(pat);
    auto off = scan_buffer(data, sizeof(data), *pat);
    assert(off && *off == 1);
    printf("  PASS: scan_buffer (found)\n");
}

void test_scan_buffer_not_found() {
    uint8_t data[] = {0x00, 0x00, 0x00, 0x00};
    auto pat = parse_pattern("48 8B 05");
    assert(pat);
    auto off = scan_buffer(data, sizeof(data), *pat);
    assert(!off);
    printf("  PASS: scan_buffer (not found)\n");
}

void test_scan_all() {
    uint8_t data[] = {0x90, 0x90, 0x00, 0x90, 0x90};
    auto pat = parse_pattern("90 90");
    assert(pat);
    auto offsets = scan_buffer_all(data, sizeof(data), *pat);
    assert(offsets.size() == 2);
    assert(offsets[0] == 0 && offsets[1] == 3);
    printf("  PASS: scan_buffer_all\n");
}

void test_empty_pattern() {
    auto r = parse_pattern("");
    assert(!r);
    printf("  PASS: empty pattern error\n");
}

int main() {
    printf("Scanner Tests\n");
    printf("=============\n");
    test_parse_pattern_ida_style();
    test_parse_pattern_single_wildcard();
    test_scan_buffer_found();
    test_scan_buffer_not_found();
    test_scan_all();
    test_empty_pattern();
    printf("\nAll scanner tests passed.\n");
    return 0;
}
