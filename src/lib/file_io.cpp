/**
 * @file file_io.cpp
 * @brief  Methods used for read/write operations on a given file
 *
 * @ref https://github.com/0xAbby/protobyte
 *
 * @author Abdullah Ada
 */
#include "../headers.h"

FileIO::FileIO() {}
FileIO::~FileIO() {}

/**
 * @brief A method to print out parsed information from a class object.
 * if file can't be read, an exception is thrown with proper message.
 *
 * @param fileObject A class object that will be either PE, ELF or MACHO, based
 * on the type the method will continue printing relevant information.
 *
 * @return none.
 */
FileIO::FileIO(std::string filename) {
  uint32_t bytes = getMagicBytes(filename);

  if (uint16_t(bytes) == PE_FILE) {
    PE pe;
    pe.init(filename);
    printPE(pe);
  } else if (bytes == ELF_FILE) {
    ELF elf;
    elf.init(filename);
    printELF(elf);
  } else if (bytes == MACHO_32_FILE || bytes == MACHO_64_FILE) {
    MACHO mach_o;
    mach_o.init(filename);
    printMachO(mach_o);
  } else if (bytes == MACHO_FAT_FILE || bytes == MACHO_FAT_CIGAM_FILE) {

  } else {
    throw std::runtime_error("Could not read magic bytes");
  }
}

/**
 * @brief A Method to print out parsed information from a class object.
 *
* @param file A MACHO class object
 *
 * @return none.
 */
void FileIO::printMachO(MACHO& file) const {
  file.printMach();
}

/**
 * @brief A Method to print out parsed information from a class object.
 *
 * @param file A PE class object
 *
 * @return none.
 */
void FileIO::printPE(PE& file) const {
  file.printPE();
}

/**
 * @brief A Method to print out parsed information from a class object.
 *
* @param file A ELF class object
 *
 * @return none.
 */
void FileIO::printELF(ELF& file) const {
  file.printElf();
}

/**
 * @brief Reads unsigned 8 bits and returns them.
 *
 * @param in An std::ifstream object with file already opened.
 *
 * @return an 8 bit unsigned integer.
 */
uint8_t FileIO::read_u8(std::ifstream& in) {
  uint8_t value = 0;
  unsigned char ch[1] = {0};

  in.read(reinterpret_cast<char*>(ch), 1);
  value = ch[0];

  return value;
}

/**
 * @brief Reads unsigned 16 bits and returns them in little endian byte order.
 *
 * @param in An std::ifstream object with file already opened.
 * @param littleEnd Indicates byte order, True: Little end. False: Big end.
 *
 * @return a 16 bit unsigned integer.
 */
uint16_t FileIO::read_u16(std::ifstream& in, bool littleEnd) {
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
 * @brief Reads unsigned 32 bits and returns them in little endian byte order.
 *
 * @param in An std::ifstream object with file already opened.
 * @param littleEnd Indicates byte order, True: Little end. False: Big end.
 *
 * @return a 32 bit unsigned integer.
 */
uint32_t FileIO::read_u32(std::ifstream& in, bool littleEnd) {
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
 * @brief Reads unsigned 64 bits and returns them in little endian byte order.
 *
 * @param in An std::ifstream object with file already opened.
 * @param littleEnd Indicates byte order, True: Little end. False: Big end.
 *
 * @return a 64 bit unsigned integer.
 */
uint64_t FileIO::read_u64(std::ifstream& in, bool littleEnd) {
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

/**
 * @brief Reads first 4 bytes as little endian byte order.
 *
 * @param filename An std::string object containing filename to be read.
 *
 * @return 4 bytes read from the beginning of the file. or 1 if it fails.
 */
uint32_t FileIO::getMagicBytes(const std::string& filename) const{
  using namespace std;
  ifstream file(filename, ios::binary);
  if (file.fail()) {
    cout << "Error, cant find file." << endl;
    return 1;
  }
  uint32_t bytes = read_u32(file, true);
  file.close();

  return bytes;
}