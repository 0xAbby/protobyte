/**
 * @file file_io.cpp
 * @brief  functions used for read/write operations on a given file
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#include "headers.h"

FileIO::FileIO() {}
FileIO::~FileIO() {}
FileIO::FileIO(std::string filename) {
  using namespace std;
  ifstream file(filename, ios::binary);
  uint32_t bytes = read_u32(file, true);
  file.close();

  file.seekg(0);
  if (uint16_t(bytes) == 0x5a4d) {
    // processing PE
    PE pe(filename);
  } else if (bytes == 0x464c457f) {
    // processing ELF
    ELF elf(filename);
  } else if (bytes == 0xfeedfacf || bytes == 0xfeedface ||
             bytes == 0xcafebabe || bytes == 0xbebafeca) {
    // processing Mach-O
    MACHO mach_o(filename);
  }
}

/**
 * @brief Reads 8 bits and returns them.
 *
 * @param in An std::ifstream object with PE file already opened.
 *
 * @return an 8 bit unsigned integer.
 */
uint8_t read_u8(std::ifstream& in) {
  uint8_t value = 0;
  unsigned char ch[1] = {0};

  in.read(reinterpret_cast<char*>(ch), 1);
  value = ch[0];

  return value;
}

/**
 * @brief Reads 16 bits and returns them in little endian byte order.
 *
 * @param in An std::ifstream object with PE file already opened.
 * @param littleEnd Indicates byte order, True: Little end. False: Big end.
 *
 * @return a 16 bit unsigned integer.
 */
uint16_t read_u16(std::ifstream& in, bool littleEnd) {
  uint16_t value = 0;
  unsigned char ch[3] = {0};

  in.read(reinterpret_cast<char*>(ch), 2);
  if (littleEnd) {
    value |= uint16_t(ch[1]) << 8;
    value |= uint16_t(ch[0]);
  } else {
    value |= uint16_t(ch[0]) << 8;
    value |= uint16_t(ch[1]);
  }
  return value;
}

/**
 * @brief Reads 32 bits and returns them in little endian byte order.
 *
 * @param in An std::ifstream object with PE file already opened.
 * @param littleEnd Indicates byte order, True: Little end. False: Big end.
 *
 * @return a 32 bit unsigned integer.
 */
uint32_t read_u32(std::ifstream& in, bool littleEnd) {
  uint32_t value = 0;
  unsigned char ch[4] = {0};

  in.read(reinterpret_cast<char*>(ch), 4);
  if (littleEnd) {
    value |= uint32_t(ch[0]);
    value |= uint32_t(ch[1]) << 8;
    value |= uint32_t(ch[2]) << 16;
    value |= uint32_t(ch[3]) << 24;
  } else {
    value |= uint32_t(ch[0]) << 24;
    value |= uint32_t(ch[1]) << 16;
    value |= uint32_t(ch[2]) << 8;
    value |= uint32_t(ch[3]);
  }
  return value;
}

/**
 * @brief Reads 64 bits and returns them in little endian byte order.
 *
 * @param in An std::ifstream object with PE file already opened.
 * @param littleEnd Indicates byte order, True: Little end. False: Big end.
 *
 * @return a 64 bit unsigned integer.
 */
uint64_t read_u64(std::ifstream& in, bool littleEnd) {
  uint64_t value = 0;
  unsigned char ch[9] = {0};

  in.read(reinterpret_cast<char*>(ch), 8);
  if (littleEnd) {
    value |= uint64_t(ch[0]);
    value |= uint64_t(ch[1]) << 8;
    value |= uint64_t(ch[2]) << 16;
    value |= uint64_t(ch[3]) << 24;
    value |= uint64_t(ch[4]) << 32;
    value |= uint64_t(ch[5]) << 40;
    value |= uint64_t(ch[6]) << 48;
    value |= uint64_t(ch[7]) << 56;
  } else {
    value |= uint64_t(ch[0]) << 56;
    value |= uint64_t(ch[1]) << 48;
    value |= uint64_t(ch[2]) << 40;
    value |= uint64_t(ch[3]) << 32;
    value |= uint64_t(ch[4]) << 24;
    value |= uint64_t(ch[5]) << 16;
    value |= uint64_t(ch[6]) << 8;
    value |= uint64_t(ch[7]);
  }
  return value;
}