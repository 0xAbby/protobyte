#include <iostream>
#include <gtest/gtest.h>
#include "../src/headers.h"

class PETest : public testing::Test {
public:
    PE pe;
    PETest() {
        pe.init("./pe/dbghelp.dll");
    }
    ~PETest() {
    }
};

TEST_F(PETest, DosHeader) { ASSERT_EQ(pe.getDosMagic(), 0x5a4d); }

TEST_F(PETest, e_lfanew) { ASSERT_EQ(pe.getElfanew(), 0x00000110); }

TEST_F(PETest, PESignature) { ASSERT_EQ(pe.getPESignature(), 0x4550); }

TEST_F(PETest, MachineType) { ASSERT_EQ(pe.getMachineType(), 0x8664); }

TEST_F(PETest, NumberOfSections) { ASSERT_EQ(pe.getNumberOfSections(), 8); }

TEST_F(PETest, DllCharacteristics) { ASSERT_EQ(pe.getDllCharacterics(), 0x4160); }

int main(int argc, char*argv[]) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}