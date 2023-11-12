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


// char *read_str(std::ifstream &in, int count) {
//   char *ch_ptr = (char*) malloc(sizeof(char)*count);
//   for(int i = 0; i < count; i++) {
//     ch_ptr[i] = fgetc(in);
//   }
//   ch_ptr[strlen(ch_ptr)] = 0;
//   return ch_ptr;
// }

// uint8_t  FileIO::read8_le(std::ifstream &in) {
//   return fgetc(in);
// }

// uint16_t  read16_le(std::ifstream &in) {
//   uint16_t value;
//   value = fgetc(in);
//   value |= (fgetc(in)<<8);
//   return value;
// }

// uint32_t  read32_le(std::ifstream &in) {
//   uint32_t value;
//   value = fgetc(in);
//   value |= (fgetc(in)<<8);
//   value |= (fgetc(in)<<16);
//   value |= (fgetc(in)<<24);
//   return value;
// }

// uint64_t  read64_le(std::ifstream &in) {
//   uint64_t value;
//   value = (uint64_t)fgetc(in);
//   value |= ((uint64_t)fgetc(in) <<8);
//   value |= ((uint64_t)fgetc(in) <<16);
//   value |= ((uint64_t)fgetc(in) <<24);
//   value |= ((uint64_t)fgetc(in) <<32);
//   value |= ((uint64_t)fgetc(in) <<40);
//   value |= ((uint64_t)fgetc(in) <<48);
//   value |= ((uint64_t)fgetc(in) <<54);

//   return value;
// }

FileIO::FileIO(int argc, char *argv[]) {

  for(int idx = 1; idx < argc; idx++) {
    // read headers
    PE pe(argv[idx]);
  }
}

FileIO::~FileIO() {
  
}


