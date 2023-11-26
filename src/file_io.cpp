//
// file_io.c:
//    functions used for read/write operations on a given file
//
//    https://github.com/0xAbby/binlyzer
//
// Author:
//  Abdullah Ada
//
#include "headers.h"
 

FileIO::FileIO(std::string filename) {
  std::ifstream file(filename, std::ios::binary | std::ios::in);
  uint32_t bytes = read32_be(file);

  file.seekg(0);
  if ( (bytes & 0x7f454c46) == 0x7f454c46) {
    // processing ELF
    ELF elf(filename);
  } else if ( (bytes & 0x5a4d0000) == 0x5a4d0000) {
    // processing PE 
    PE pe(filename);
  } else if ( (bytes & 0xcffaedfe) == 0xcffaedfe) {
    std::cout << "\nMach-O\n";
  }
}
