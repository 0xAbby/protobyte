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

class FileIO {
private:
  FILE *in;

public:
  FileIO(int argc, char *argv[]);
  ~FileIO();



  uint8_t read8_le(FILE *in);
};


#endif
