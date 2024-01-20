/**
 * @file elftest.h
 * @brief  definitions and unit tests for ELF format.
 *
 * @ref https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#ifndef ELFTEST_H
#define ELSTEST_H

#include <iostream>
#include <gtest/gtest.h>
#include "../headers.h"

/**
 * @brief A class holding definitions for ELF related tests.
 *
 **/
class ELFTest : public testing::Test {
 public:
  ELF elf;
  ELFTest() { elf.init("../samples/elf/lshw"); }
  ~ELFTest() =default;
};

/**
 * @brief A unit test checking magic bytes indicating ELF file.
 *
 */
TEST_F(ELFTest, MagicBytes) {
  ASSERT_TRUE(elf.getMagicBytes() == 0x7f454c46);
}

/**
 * @brief A unit test checking e_ident 6th's byte,
 * which indicates byte's order (1: LSB / 2: MSB)
 */
TEST_F(ELFTest, ByteOrder) {
  ASSERT_TRUE(elf.getEi_data() == 0x01);
}

/**
 * @brief A unit test checking start address
 */
TEST_F(ELFTest, e_ntry) {
  ASSERT_TRUE(elf.getE_entry() == 0x1c1b0);
}

/**
 * @brief A unit test checking section header offset
 */
TEST_F(ELFTest, e_shoff) {
  ASSERT_TRUE(elf.getE_shoff() == 0xe0d08);
}

/**
 * @brief A unit test checking program header offset
 */
TEST_F(ELFTest, e_phoff) {
  ASSERT_TRUE(elf.getE_phoff() == 0x40);
}

/**
 * @brief A unit test checking 'lshw' 17th's section 
 * table element, with name '.text'
 */
TEST_F(ELFTest, sectionTableText) {
  ASSERT_TRUE(elf.getSectionHeaders()[16].getS_name().compare(0,5,".text") == 0);
}

/**
 * @brief A unit test checking 'lshw' 17th's section 
 * table element size
 */
TEST_F(ELFTest, sectionTableTextSize) {
  ASSERT_TRUE(elf.getSectionHeaders()[16].getSh_size() == 0xABDF6);
}

/**
 * @brief A unit test checking 'lshw' 17th's section 
 * table element offset
 */
TEST_F(ELFTest, sectionTableTextOffset) {
  ASSERT_TRUE(elf.getSectionHeaders()[16].getSh_offset() == 0x10470);
}

/**
 * @brief A unit test checking 'lshw' 28th's section 
 * table element, with name '.data'
 */
TEST_F(ELFTest, sectionTableData) {
  ASSERT_TRUE(elf.getSectionHeaders()[27].getS_name().compare(0, 5, ".data") == 0);
}

/**
 * @brief A unit test checking 'lshw' 28th's section 
 * table element address
 */
TEST_F(ELFTest, sectionTableDataAddress) {
  ASSERT_TRUE(elf.getSectionHeaders()[27].getSh_addr() == 0xE1000);
}

/**
 * @brief A unit test checking 'lshw' 28th's section 
 * table element section size
 */
TEST_F(ELFTest, sectionTableDataSize) {
  ASSERT_TRUE(elf.getSectionHeaders()[27].getSh_size() == 0xBA4);
}

#endif