/**
 * @file macho.cpp
 * @brief  Implements functions that deals with Mach-O structures
 *        read and save information in a PE class object members.
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */

#include "headers.h"

MACHO::MACHO(std::string filename) {
  init(filename);
}

void MACHO::init(std::string filename) {
  std::ifstream file(filename, std::ios::binary);

  // parse32_mach(file);
  // parse64_mach(file);
  // parse_fat(file);

  // print basic info
}