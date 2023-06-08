#include "bypasscore/binary/pe.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace bypasscore::binary;

// Build a minimal valid PE32+ in memory for testing
std::vector<uint8_t> build_minimal_pe() {
    std::vector<uint8_t> pe(4096, 0);
    size_t off = 0;

    // DOS header
    pe[0] = 'M'; pe[1] = 'Z';
    *reinterpret_cast<int32_t*>(&pe[60]) = 0x80; // e_lfanew

    // PE signature at 0x80
    off = 0x80;
    pe[off] = 'P'; pe[off+1] = 'E'; pe[off+2] = 0; pe[off+3] = 0;
    off += 4;

    // COFF header
    auto* coff = reinterpret_cast<CoffHeader*>(&pe[off]);
    coff->machine = MACHINE_AMD64;
    coff->number_of_sections = 1;
    coff->size_of_optional_header = sizeof(OptionalHeader64);
    off += sizeof(CoffHeader);

    // Optional header (PE32+)
    auto* opt = reinterpret_cast<OptionalHeader64*>(&pe[off]);
    opt->magic = 0x20B;
    opt->address_of_entry_point = 0x1000;
    opt->image_base = 0x140000000;
    opt->section_alignment = 0x1000;
    opt->file_alignment = 0x200;
    opt->size_of_image = 0x3000;
    opt->size_of_headers = 0x200;
    opt->number_of_rva_and_sizes = 16;
    off += sizeof(OptionalHeader64);

    // Section header: .text
    auto* sec = reinterpret_cast<SectionHeader*>(&pe[off]);
    std::memcpy(sec->name, ".text\0\0\0", 8);
    sec->virtual_size = 0x100;
    sec->virtual_address = 0x1000;
    sec->size_of_raw_data = 0x200;
    sec->pointer_to_raw_data = 0x200;
    sec->characteristics = 0x60000020; // CODE | EXECUTE | READ

    return pe;
}

void test_parse_valid_pe() {
    auto data = build_minimal_pe();
    auto result = PeImage::parse(data.data(), data.size());
    assert(result);
    assert(result->is_64bit());
    assert(result->machine() == MACHINE_AMD64);
    assert(result->entry_point_rva() == 0x1000);
    assert(result->image_base() == 0x140000000);
    assert(result->sections().size() == 1);
    assert(result->sections()[0].name == ".text");
    printf("  PASS: parse valid PE64\n");
}

void test_parse_invalid_dos() {
    uint8_t data[] = {0x00, 0x00, 0x00, 0x00};
    auto result = PeImage::parse(data, sizeof(data));
    assert(!result);
    printf("  PASS: reject invalid DOS header\n");
}

void test_rva_to_offset() {
    auto data = build_minimal_pe();
    auto result = PeImage::parse(data.data(), data.size());
    assert(result);
    auto off = result->rva_to_offset(0x1000);
    assert(off && *off == 0x200);
    auto no_off = result->rva_to_offset(0xFFFF);
    assert(!no_off);
    printf("  PASS: rva_to_offset\n");
}

void test_find_section() {
    auto data = build_minimal_pe();
    auto result = PeImage::parse(data.data(), data.size());
    assert(result);
    auto* sec = result->find_section(".text");
    assert(sec && sec->is_executable());
    assert(!result->find_section(".data"));
    printf("  PASS: find_section\n");
}

int main() {
    printf("PE Parser Tests\n");
    printf("================\n");
    test_parse_valid_pe();
    test_parse_invalid_dos();
    test_rva_to_offset();
    test_find_section();
    printf("\nAll PE tests passed.\n");
    return 0;
}
