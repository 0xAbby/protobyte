/**
 * @file mach_o-test.h
 * @brief  definitions and unit tests for Mach-O format.
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#ifndef MACHO_TEST_H
#define MACHO_TEST_H

#include <iostream>
#include <gtest/gtest.h>
#include "../headers.h"

// class MACHO_OTest : public testing::Test {
// public:
//     ELF elf;
//     ELFTest() {
//         elf.init("../../test_samples/elf/lshw");
//     }
//     ~ELFTest() {
//     }
// };

// // last two bits in the 5th byte of magic bytes indicates whether ELF is 32 /
// 64 bit
// // 2 is for 64bit
// TEST_F(ELFTest, e_ident) {
//     ASSERT_TRUE(elf.getE_ident()[4] & 2 );
// }

// // e_ident 6th's byte indicates byte's order (1: LSB / 2: MSB)
// TEST_F(ELFTest, ByteOrder) {
//     ASSERT_TRUE(elf.getE_ident()[5] & 1 );
// }

#endif