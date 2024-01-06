/**
 * @file macho.cpp
 * @brief  Implements functions that deals with Mach-O structures
 *        read and save information in a MACHO class object members.
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */

#include "headers.h"

/**
 * @brief constructor for PE class objects that helps with starting parsing operation.
 *
 * @param filename a string for a file to be opened and parsed.
 *
 * @return none.
 */
MACHO::MACHO(std::string filename) {
  //init(filename);
}

/**
 * @brief Open file in binary mode and calls parsing method.
 *
 * @param filename a string for a file to be opened and parsed.
 *
 * @return none.
 */
void MACHO::init(std::string filename) {
  std::ifstream file(filename, std::ios::binary);
  magicBytes_u32 = FileIO::read_u32(file, true);

  if (magicBytes_u32 == 0xFEEDFACF) {
    // parse64_mach(file);
  } else if (magicBytes_u32 == 0xFEEDFACE) {
    parse32_macho(file);
  } else if (magicBytes_u32 == 0xCAFEBABE || magicBytes_u32 == 0xBEBAFECA) {
    // parseFatMachO(file);
  }
}

void MACHO::parse32_macho(std::ifstream& file) {

}

MACHO::MACHO() {}
MACHO::~MACHO() {}