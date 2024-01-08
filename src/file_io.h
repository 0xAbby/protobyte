/**
 * @file file_io.h
 * @brief  definitions for class / functions used to interact with the file,
 *      reading and writing operations.
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */

#ifndef FILE_IO_H
#define FILE_IO_H

#include "headers.h"
#include "macho.h"
#include "pe.h"
#include "elf.h"

/**
 * @brief FileIO class handles files that will parsed.
 */
class FileIO {
 public:
  // disabling move/copy constructors
  FileIO(FileIO&) = delete;
  FileIO(FileIO&&) = delete;
  FileIO& operator=(FileIO&) = delete;

  FileIO();
  FileIO(std::string);
  virtual ~FileIO();

  void printPE(PE&) const;
  void printELF(ELF&) const;
  uint32_t fileID(std::string) const;
  void printMachO(MACHO&) const;

  enum fileType { MACHO_32_FILE = 0xFEEDFACE, 
                  MACHO_64_FILE = 0xFEEDFACF,
                  MACHO_FAT_FILE = 0xCAFEBABE,
                  MACHO_FAT_CIGAM_FILE = 0xBEBAFECA,
                  PE_FILE = 0x5A4D,
                  ELF_FILE = 0x464C457F};

  /**
   * @brief Functions used for reading unsigned bytes, of various lengths.
   *
   * @param ifstream an object to a stream file that is alread opened.
   * @param bool Indiactes byte order, True: little endian, False: big endian.
   *
   * @return Each method returns a specific size based on
   * its name, 8 bits, 16, 32 and 64.
   */
  static uint8_t read_u8(std::ifstream&);
  static uint16_t read_u16(std::ifstream&, bool);
  static uint32_t read_u32(std::ifstream&, bool);
  static uint64_t read_u64(std::ifstream&, bool);
};

#endif
