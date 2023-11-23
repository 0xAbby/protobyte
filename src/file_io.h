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
    FileIO() { }
    FileIO(std::string filename);

    
    template <typename T> T read8_le(std::ifstream &in);
    template <typename T> T read16_le(std::ifstream &in);
    template <typename T> T read32_le(std::ifstream &in);
    template <typename T> T read64_le(std::ifstream &in);
  
};


#endif
