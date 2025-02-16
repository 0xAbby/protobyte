/**
 * @file runTests.cpp
 * @brief  Unit tests main source code.
 *
 * @ref https://github.com/0xAbby/protobyte
 *
 * @author Abdullah Ada
 */

#include "elftest.h"
#include "petest.h"
#include "mach_o-test.h"
#include "hashtest.h"
#include "fileio_test.h"

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}