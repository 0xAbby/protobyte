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

template <typename T> T 
FileIO::read8_le(std::ifstream &in) {
  uint8_t value = 0;
  char ch[1] = {0};

  in.read(ch, 1);
  value = ch[0];
  
  return value;
}

template <typename T> T
 FileIO::read16_le(std::ifstream &in) {
  uint16_t value = 0;
  char ch[3] = {0};

  in.read(ch, 2);
  value = ch[0];
  value |= ch[1] << 8;
  
  return value;
}

template <typename T> T 
 FileIO::read32_le(std::ifstream &in) {
  uint32_t value = 0;
  char ch[4] = {0};

  in.read(ch, 4);
  value = ch[0];
  value |= ch[1] << 8;
  value |= ch[2] << 16;
  value |= ch[3] << 24;
  
  return value;
}

template <typename T> T 
 FileIO::read64_le(std::ifstream &in) {
  uint64_t value = 0;
  char ch[9] = {0};

  in.read(ch, 8);
  value = ch[0];
  value |= long(ch[1]) << 8;
  value |= long(ch[2]) << 16;
  value |= long(ch[3]) << 24;
  value |= long(ch[4]) << 32;
  value |= long(ch[5]) << 40;
  value |= long(ch[6]) << 48;
  value |= long(ch[7]) << 54;
  
  return value;
}

FileIO::FileIO(std::string filename) {  
  PE pe(filename);
}