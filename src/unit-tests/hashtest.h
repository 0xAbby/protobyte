/**
 * @file hashtest.h
 * @brief  definitions and unit tests for hashing functions.
 *
 * @ref https://github.com/0xAbby/protobyte
 *
 * @author Abdullah Ada
 */
#ifndef HASHTEST_H
#define HASHEST_H

#include <iostream>
#include <gtest/gtest.h>
#include "../headers.h"

/**
 * @brief A class holding definitions for ELF related tests.
 *
 **/
class HASHTest : public testing::Test {
 public:
  MD5Hasher md5;
  SHA1     sha1;

  std::string md5_hash;
  std::string sha1_hash;


  HASHTest() { 
    // MD5 / SHA1 hashes
    md5.MD5FileContent("../samples/mach-o/MachO-iOS-armv7-armv7s-arm64", md5_hash);
    sha1_hash = sha1.from_file("../samples/elf/libresolv.so.2");
   }
  ~HASHTest() =default;
};

/**
 * @brief basic sha1 test
 *
 */
TEST_F(HASHTest, SHA1_TEST) {
  ASSERT_EQ(sha1_hash, "19188e369c9b2909944d3330dd4e73c338e6f414");
}

/**
 * @brief basic md5 test
 *
 */
TEST_F(HASHTest, MD5_test) {
  ASSERT_EQ(md5_hash, "750338e86da4e5c8c318b885ba341d82");
}

#endif
