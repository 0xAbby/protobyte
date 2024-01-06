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

  if (magicBytes_u32 == 0xFEEDFACF || magicBytes_u32 == 0xFEEDFACE) {
    parseX86_macho(file);
  } else if (magicBytes_u32 == 0xCAFEBABE || magicBytes_u32 == 0xBEBAFECA) {
    parseUniMacho(file);
  }
}

void MACHO::parseUniMacho(std::ifstream& file) {


}
/*** 
 * @brief parses x86 Mach-O format (32 and 64 bit).
 * @param file an ifstream object file, with the file already opened and set at offset 4
 * 
 * @return none.
 */
void MACHO::parseX86_macho(std::ifstream& file) {
  cpuType_u32 = FileIO::read_u32(file, true);
  cpuSubtype_u32 = FileIO::read_u32(file, true);
  fileType_u32 = FileIO::read_u32(file, true);
  numLoadCommands_u32 = FileIO::read_u32(file, true);
  sizeOfLoadCommand_u32 = FileIO::read_u32(file, true);
  flags_u32 = FileIO::read_u32(file, true);

  // skip resreved bytes if processing x86-64 file
  if (magicBytes_u32 == 0xFEEDFACF) reserved_u32 = FileIO::read_u32(file, true);

  // only LoadCommands of Type segments will be parsed initially, 
  // later code can be expanded for more types.
  for (uint32_t idx = 0; idx < sizeOfLoadCommand_u32 - 1; idx++) {
    LoadCommand lCommand;
    
    // save current offset, to jump to next LoadCommand.
    uint32_t next_offset = file.tellg();

    // for now only scanning LoadCommands of Type 'Segment'.
    lCommand.setCommand(FileIO::read_u32(file, true));
    uint32_t commandType = lCommand.getCommand();
    if (commandType != 1 && commandType != 0x19) break;

    lCommand.setCommandSize(FileIO::read_u32(file, true));

    if (cpuType_u32 == 7) { // x86 Mach file
      lCommand.setSegmentName(file);
      lCommand.setVMaddress(FileIO::read_u32(file, true));
      lCommand.setVMSize(FileIO::read_u32(file, true));
      lCommand.setFileOffset(FileIO::read_u32(file, true));
      lCommand.setFileSize(FileIO::read_u32(file, true));
      lCommand.setMaxProtection(FileIO::read_u32(file, true));
      lCommand.setInitialProtection(FileIO::read_u32(file, true));
      lCommand.setNumberOfSections(FileIO::read_u32(file, true));
      lCommand.setFlags(FileIO::read_u32(file, true));
    } else if (cpuType_u32 == 0x1000007) { // x86-64 mach file
      lCommand.setSegmentName(file);
      lCommand.setVMaddress(FileIO::read_u64(file, true));
      lCommand.setVMSize(FileIO::read_u64(file, true));
      lCommand.setFileOffset(FileIO::read_u64(file, true));
      lCommand.setFileSize(FileIO::read_u64(file, true));
      lCommand.setMaxProtection(FileIO::read_u32(file, true));
      lCommand.setInitialProtection(FileIO::read_u32(file, true));
      lCommand.setNumberOfSections(FileIO::read_u32(file, true));
      lCommand.setFlags(FileIO::read_u32(file, true));
    }
    loadCommand.push_back(lCommand);

    // skip to next loadCommand structure 
    next_offset += lCommand.getCommandSize();
    file.seekg(next_offset);
  }


  // skip to next LCommand structure and code_signature
  file.seekg( (sizeOfLoadCommand_u32 + 0x24) + std::ios::cur); 
}


/* LoadCommand-specific methods */
void LoadCommand::setCommand(uint32_t command) {
  this->command_u32 = command;
}
void LoadCommand::setCommandSize(uint32_t size) {
  this->commandSize_u32 = size;
}
void LoadCommand::setSegmentName(std::ifstream& file) {
  char name[16] = {0};
  file.get(name, 17);
  this->segmentName = name;
}
void LoadCommand::setVMaddress(uint64_t vm) {
  this->vmAddress_u64 = vm;
}
void LoadCommand::setVMSize(uint64_t size) {
  this->vmSize_u64 = size;
}
void LoadCommand::setFileOffset(uint64_t fileOffset) {
  this->fileOffset_u64 = fileOffset;
}
void LoadCommand::setFileSize(uint64_t fileSize) {
  this->fileSize_u64 = fileSize;
}

uint32_t LoadCommand::getCommand() {
  return this->command_u32;
}
uint32_t LoadCommand::getCommandSize() const {
  return this->commandSize_u32;
}
std::string LoadCommand::getSegmentName() const {
  return this->segmentName;
}
uint64_t LoadCommand::getVMaddress() const {
  return this->vmAddress_u64;
}
uint64_t LoadCommand::getVMSize() const {
  return this->vmSize_u64;
}
uint64_t LoadCommand::getFileOffset() const {
  return this->fileOffset_u64;
}
void LoadCommand::setMaxProtection(uint32_t maxPro) {
  this->maximumProtection_u32 = maxPro;
}
void LoadCommand::setInitialProtection(uint32_t InitPro) {
  this->initialProtection_u32 = InitPro;
}
void LoadCommand::setNumberOfSections(uint32_t sections) {
  this->numberOfSections_u32 = sections;
}
void LoadCommand::setFlags(uint32_t flags) {
  this->flags_u32 = flags;
}

uint64_t LoadCommand::getFileSize() const { 
  return this->fileSize_u64;
}
uint32_t LoadCommand::getMaxProtection() const {
  return this->maximumProtection_u32;
}
uint32_t LoadCommand::getInitialProtection() const {
  return this->initialProtection_u32;
}
uint32_t LoadCommand::getNumberOfSections() const {
  return this->numberOfSections_u32;
}
uint32_t LoadCommand::getFlags() const {
  return this->flags_u32;
}

/***************************************************/

void MACHO::setMagicBytes(uint32_t magic) {
  this->magicBytes_u32 = magic;
}
void MACHO::setCputType(uint32_t type) {
  this->cpuType_u32 = type;
}
void MACHO::setCpuSubType(uint32_t subtype) {
  this->cpuSubtype_u32 = subtype;
}
void MACHO::setFileType(uint32_t fileType) {
  this->fileType_u32 = fileType;
}
void MACHO::setNumLoadCommands(uint32_t number) {
  this->numLoadCommands_u32 = number;
}
void MACHO::setSizeOfLoadCommand(uint32_t size) {
  this->sizeOfLoadCommand_u32 = size;
}

uint32_t MACHO::getMagicBytes() const {
  return this->magicBytes_u32;
}
uint32_t MACHO::getCputType() const {
  return this->cpuType_u32;
}
uint32_t MACHO::getCpuSubType() const {
  return this->cpuSubtype_u32;
}
uint32_t MACHO::getFileType() const {
  return this->fileType_u32;
}
uint32_t MACHO::getNumLoadCommands() const {
  return this->numLoadCommands_u32;
}
uint32_t MACHO::getSizeOfLoadCommand() const {
  return this->sizeOfLoadCommand_u32;
}

std::vector<LoadCommand> MACHO::getLoadCommand() const {
  return this->loadCommand;
}

MACHO::MACHO() {}
MACHO::~MACHO() {}