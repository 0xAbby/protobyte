// file_io.h:
//    definitions for class / functions used to interact with the file,
//    reading and writing operations.
//
//  https://github.com/0xAbby/binlyzer
//
// Author:
//  Abdullah Ada
//

#ifndef FILE_IO_H
#define FILE_IO_H

#include "headers.h"

uint8_t read_u8(std::ifstream& in);
uint16_t read_u16(std::ifstream& in, bool littleEnd);
uint32_t read_u32(std::ifstream& in, bool littleEnd);
uint64_t read_u64(std::ifstream& in, bool littleEnd);

class FileIO {
 private:
 public:
  FileIO();
  ~FileIO();
  FileIO(std::string filename);
};

#endif
