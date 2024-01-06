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
class FileIO : public PE, public MACHO, public ELF {
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
  void printMachO(MACHO&) const;

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
