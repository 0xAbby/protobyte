/** 
 * @file runTests.cpp
 * @brief  Unit tests main source code.
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
*/

#include "elftest.h"
#include "petest.h"
 
int main(int argc, char*argv[]) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}