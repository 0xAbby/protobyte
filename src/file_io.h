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
  

public:
  FileIO(int argc, char *argv[]);
  ~FileIO();
  
  uint16_t read16_le(std::ifstream &in);
};


#endif
