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

class MACHO_Test : public testing::Test {
public:
    MACHO mach_o;
    MACHO_Test() {
        mach_o.init("../../samples/mach-o/MachO-OSX-x64-ls");
    }
    ~MACHO_Test() {
    }
};


TEST_F(MACHO_Test, MagicBytes) {
    ASSERT_TRUE(mach_o.getMagicBytes() == 0xFEEDFACF );
}

TEST_F(MACHO_Test, CPUtype) {
    ASSERT_TRUE(mach_o.getCputType() == 0x1000007 );
}

TEST_F(MACHO_Test, CPUsubtype) {
    ASSERT_TRUE(mach_o.getCpuSubType() == 0x80000003 );
}

TEST_F(MACHO_Test, LoadCommandSegmentName) {
    ASSERT_TRUE(mach_o.getLoadCommand()[1].getSegmentName() == "__TEXT" );
}

TEST_F(MACHO_Test, LoadCommandSegmentSize) {
    ASSERT_TRUE(mach_o.getLoadCommand()[1].getCommandSize() == 0x228 );
}


#endif