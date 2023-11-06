#include <iostream>
#include <gtest/gtest.h>
#include "../src/headers.h"

TEST(Test1, DosHeader) {
    // prepare test case: parsing known file
    PE pe("pe/samples/dbghelp.dll");

    ASSERT_EQ(pe.getDosMagic(), 0x4d5a);
    
}


TEST(Test2, e_lfanew) {
    PE pe("pe/samples/dbghelp.dll");
    ASSERT_TRUE(pe.getElfanew() == 0x00000110);
}

int main(int argc, char*argv[]) {

    testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}