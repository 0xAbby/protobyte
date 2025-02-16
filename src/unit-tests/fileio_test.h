/**
 * @file fileio_test.h
 * @brief  definitions and unit tests for file_io class.
 *
 * @ref https://github.com/0xAbby/protobyte
 *
 * @author Abdullah Ada
 */
#ifndef FILEIO_TEST_H
#define FILEIO_TEST_H

#include <iostream>
#include <gtest/gtest.h>
#include "../headers.h"

/**
 * @brief A class holding definitions for Mach-O related tests.
 *
 * */
class FILEIO_TEST : public testing::Test {
public:
    FILEIO_TEST() {    }
    ~FILEIO_TEST() =default;
};


TEST_F(FILEIO_TEST, File_IO_exception) {
    std::string filename = "../samples/dummy_file";

    // expecting an exception
    EXPECT_THROW(FileIO test_file(filename), std::runtime_error);

    filename = "../samples/pe/win32k.sys";

    // not expecting exception
    EXPECT_NO_THROW(FileIO test_file(filename));
}

#endif