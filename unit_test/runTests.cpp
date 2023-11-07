#include <iostream>
#include <gtest/gtest.h>
#include "../src/headers.h"

class PETest : public testing::Test {
public:
    PE pe;
    PETest() {
        pe.init("./pe/samples/dbghelp.dll");
    }
    ~PETest() {
    }
};

TEST_F(PETest, DosHeader) {
    ASSERT_EQ(pe.getDosMagic(), 0x5a4d);
}

TEST_F(PETest, e_lfanew) {
    ASSERT_EQ(pe.getElfanew(), 0x00000110);
}

TEST_F(PETest, PE_Signature) {
    ASSERT_EQ(pe.getPESignature(), 0x4550);
}

int main(int argc, char*argv[]) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}