/**
 * @file elftest.h
 * @brief  definitions and unit tests for ELF format.
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#ifndef ELFTEST_H
#define ELSTEST_H

#include <iostream>
#include <gtest/gtest.h>
#include "../headers.h"

class ELFTest : public testing::Test {
 public:
  ELF elf;
  ELFTest() { elf.init("../../samples/elf/lshw"); }
  ~ELFTest() {}
};

// last two bits in the 5th byte of magic bytes indicates whether ELF is 32 / 64
// bit 2 is for 64bit
TEST_F(ELFTest, MagicBytes) {
  ASSERT_TRUE(elf.getMagicBytes() == 0x7f454c46);
}

// e_ident 6th's byte indicates byte's order (1: LSB / 2: MSB)
TEST_F(ELFTest, ByteOrder) {
  ASSERT_TRUE(elf.getEi_data() == 0x01);
}

#endif