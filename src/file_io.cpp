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
  using namespace std;
  ifstream file(filename, ios::binary | ios::in);
  uint32_t bytes = read32_be(file);

  cout << "in FileIO.." << endl;
  file.seekg(0);
  if (bytes>>16 == 0x5a4d) {
    // processing PE 
    PE pe(filename);
  } else if (bytes == 0x7f454c46) {
    // processing ELF
    // ELF elf(filename);
  } else if (bytes == 0xcffaedfe) {
    // processing Mach-O
    // MachO macho(filename);
    cout << "\nMach-O\n";
  }
}
