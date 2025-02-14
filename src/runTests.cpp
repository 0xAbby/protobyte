/**
 * @file runTests.cpp
 * @brief  Unit tests main source code.
 *
 * @ref https://github.com/0xAbby/protobyte
 *
 * @author Abdullah Ada
 */

#include "include/elftest.h"
#include "include/petest.h"
#include "include/mach_o-test.h"

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}