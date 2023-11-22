#include "bypasscore/binary/disasm.h"
#include <cassert>
#include <cstdio>

using namespace bypasscore::binary;

void test_nop() {
    uint8_t code[] = {0x90}; // NOP
    LengthDisasm d(LengthDisasm::Mode::X64);
    assert(d.length(code) == 1);
    printf("  PASS: NOP (1 byte)\n");
}

void test_push_rbp() {
    uint8_t code[] = {0x55}; // push rbp
    LengthDisasm d(LengthDisasm::Mode::X64);
    assert(d.length(code) == 1);
    printf("  PASS: push rbp (1 byte)\n");
}

void test_mov_rsp_rbp() {
    uint8_t code[] = {0x48, 0x89, 0xE5}; // mov rbp, rsp (REX.W + MOV)
    LengthDisasm d(LengthDisasm::Mode::X64);
    assert(d.length(code) == 3);
    printf("  PASS: mov rbp, rsp (3 bytes)\n");
}

void test_sub_rsp_imm8() {
    uint8_t code[] = {0x48, 0x83, 0xEC, 0x20}; // sub rsp, 0x20
    LengthDisasm d(LengthDisasm::Mode::X64);
    assert(d.length(code) == 4);
    printf("  PASS: sub rsp, 0x20 (4 bytes)\n");
}

void test_call_rel32() {
    uint8_t code[] = {0xE8, 0x12, 0x34, 0x56, 0x78}; // call rel32
    LengthDisasm d(LengthDisasm::Mode::X64);
    assert(d.length(code) == 5);
    printf("  PASS: call rel32 (5 bytes)\n");
}

void test_jmp_rel32() {
    uint8_t code[] = {0xE9, 0xAA, 0xBB, 0xCC, 0xDD}; // jmp rel32
    LengthDisasm d(LengthDisasm::Mode::X64);
    assert(d.length(code) == 5);
    printf("  PASS: jmp rel32 (5 bytes)\n");
}

void test_ret() {
    uint8_t code[] = {0xC3}; // ret
    LengthDisasm d(LengthDisasm::Mode::X64);
    assert(d.length(code) == 1);
    printf("  PASS: ret (1 byte)\n");
}

void test_mov_rax_imm64() {
    uint8_t code[] = {0x48, 0xB8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    LengthDisasm d(LengthDisasm::Mode::X64);
    assert(d.length(code) == 10);
    printf("  PASS: movabs rax, imm64 (10 bytes)\n");
}

void test_jcc_rel8() {
    uint8_t code[] = {0x74, 0x0A}; // jz +10
    LengthDisasm d(LengthDisasm::Mode::X64);
    assert(d.length(code) == 2);
    printf("  PASS: jz rel8 (2 bytes)\n");
}

void test_calc_overwrite() {
    uint8_t code[] = {0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20};
    LengthDisasm d(LengthDisasm::Mode::X64);
    size_t sz = d.calc_overwrite_size(code, 5);
    assert(sz >= 5);
    printf("  PASS: calc_overwrite_size >= 5 (got %zu)\n", sz);
}

int main() {
    printf("Disassembler Tests\n");
    printf("===================\n");
    test_nop();
    test_push_rbp();
    test_mov_rsp_rbp();
    test_sub_rsp_imm8();
    test_call_rel32();
    test_jmp_rel32();
    test_ret();
    test_mov_rax_imm64();
    test_jcc_rel8();
    test_calc_overwrite();
    printf("\nAll disassembler tests passed.\n");
    return 0;
}
