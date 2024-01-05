/**
 * @file macho.h
 * @brief  Definitions and declarations for Mach-O module
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#ifndef MACHO_H
#define MACHO_H

#include "headers.h"

class MachOSection {
 public:
 private:
  std::string sectionName;  // 17 bytes.
  std::string segmentName;  // 17 bytes
  uint64_t address_u64;
  uint64_t size_u64;
  uint32_t offset_u32;
  uint32_t sectionAlignment_u32;
  uint32_t relocationEntryOfsset_u32;
  uint32_t numberOfRelocationEntries_u32;
};

class LoadCommand {
 public:
 private:
  uint32_t command_u32;
  uint32_t commandSize_u32;
  std::string segmentName;  // 17 bytes;
  uint64_t vmAddress_u64;
  uint64_t vmSize_u64;
  uint64_t fileOffset_u64;
  uint64_t fileSize_u64;
  uint32_t maximumProtection_u32;
  uint32_t initialProtection_u32;
  uint32_t numberOfSections_u32;
  uint32_t flags_u32;

  MachOSection* section;  // an array of section objects.
};

class MACHO {
 public:
  MACHO() {}
  ~MACHO() {}
  MACHO(std::string filename);
  void init(std::string filename);

 private:
  // header
  uint32_t magicBytes_u32;
  uint32_t cpuType_U32;
  uint32_t cpuSubtype_u32;
  uint32_t fileType_u32;
  uint32_t numLoadCommands_u32;
  uint32_t sizeOfLoadCommand_u32;
  uint32_t flags_u32;
  uint32_t resreved_u32;

  LoadCommand* loadCommand;  // an array of loadcommand objects
};

#endif