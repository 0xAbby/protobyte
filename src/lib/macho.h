/**
 * @file macho.h
 * @brief  Definitions and declarations for Mach-O module
 *
 * @ref  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#ifndef MACHO_H
#define MACHO_H

#include "../headers.h"

/**
 * @brief Definitions for sections in Mach-O files.
*/
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

/**
 * @brief holds information Variable size commands that 
 * specify the layout and linkage characteristics of of the file.
 */
class LoadCommand {
 public:
  void setCommand(uint32_t);
  void setCommandSize(uint32_t);
  void setSegmentName(std::ifstream&);
  void setVMaddress(uint64_t);
  void setVMSize(uint64_t);
  void setFileOffset(uint64_t);
  void setFileSize(uint64_t);
  void setMaxProtection(uint32_t);
  void setInitialProtection(uint32_t);
  void setNumberOfSections(uint32_t);
  void setFlags(uint32_t);

  uint32_t getCommandType();
  uint32_t getCommandSize() const;
  std::string getSegmentName() const;
  uint64_t getVMaddress() const;
  uint64_t getVMSize() const;
  uint64_t getFileOffset() const;
  uint64_t getFileSize() const;
  uint32_t getMaxProtection() const;
  uint32_t getInitialProtection() const;
  uint32_t getNumberOfSections() const;
  uint32_t getFlags() const;

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

/**
 * @brief holds information for Mach_o file format, carries out Mach-O specific
 * operations, loading, reading displaying header info.
 * @see https://en.wikipedia.org/wiki/Mach-O
 * @see https://developer.apple.com/library/archive/documentation/Performance
 * /Conceptual/CodeFootprint/Articles/MachOOverview.html
 * @see https://github.com/aidansteele/osx-abi-macho-file-format-reference
 */
class MACHO {
 public:
 // disabling move/copy constructors
  //MACHO(MACHO&) = delete;
  //MACHO(MACHO&&) = delete;
  MACHO & operator=( MACHO&) = delete;

  MACHO();
  virtual ~MACHO();
  MACHO(const std::string&);

  void init(const std::string&);
  void parseX86_macho(std::ifstream&);
  void parseUniMacho(std::ifstream&);

  void setMagicBytes(uint32_t);
  void setCputType(uint32_t);
  void setCpuSubType(uint32_t);
  void setFileType(uint32_t);
  void setNumLoadCommands(uint32_t);
  void setSizeOfLoadCommand(uint32_t);
  void mapFlagDefinitions();
  void printFlag(uint32_t, u_int32_t);
  void printMach();

  uint32_t getMagicBytes() const;
  uint32_t getCputType() const;
  uint32_t getCpuSubType() const;
  uint32_t getFileType() const;
  uint32_t getNumLoadCommands() const;
  uint32_t getSizeOfLoadCommand() const;
  uint32_t getFlags() const;
  std::vector<LoadCommand> getLoadCommand() const;

 private:
  // header
  uint32_t magicBytes_u32;
  uint32_t cpuType_u32;
  uint32_t cpuSubtype_u32;
  uint32_t fileType_u32;
  uint32_t numLoadCommands_u32;
  uint32_t sizeOfLoadCommand_u32;
  uint32_t flags_u32;
  uint32_t reserved_u32; // x64 specific
  
  
  
  std::vector<LoadCommand> loadCommand; 

  std::map<uint32_t, std::string> magicMap_m;
  std::map<uint32_t, std::string> cputType_m;
  std::map<uint32_t, std::string> headerFileType_m;
  std::map<uint32_t, std::string> headerFlags_m;
  std::map<uint32_t, std::string> loadCommandType_m;

  enum MachMaps { magictypes = 0,
                  cputypes = 1,
                  headerfiltype,
                  headerflags,
                  loadcommandtype};
};

#endif