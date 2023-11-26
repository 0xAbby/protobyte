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

TEST_F(PETest, BaseOfCode) { ASSERT_EQ(pe.getBaseOfCode(), 0x1000); }

TEST_F(PETest, SectionAlignment) { ASSERT_EQ(pe.getSectionAlignment(),  0x1000); }

TEST_F(PETest, NumberOfRVA) { ASSERT_EQ(pe.getnumberOfRvaAndSizes(), 0x10); }

TEST_F(PETest, Checksum) { ASSERT_EQ(pe.getChecksum(), 0x001E7393); }

// sections is arranged into 'sections' array, in file sample used here
// 0 means first section, which is ".text"
TEST_F(PETest, textSection) { ASSERT_TRUE(pe.getSection(0).getName().compare(".text")); }

TEST_F(PETest, textVirtualSize) { ASSERT_TRUE(pe.getSection(0).getVirtualSize() == 0x001590DE); }

// data section is the 3rd in the 'sections' array
TEST_F(PETest, dataVirtualAddress) { ASSERT_TRUE(pe.getSection(2).getVirtualAddress() == 0x001B4000); }

int main(int argc, char*argv[]) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}