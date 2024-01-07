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
  for (uint32_t idx = 0; idx < numLoadCommands_u32 ; idx++) {
    LoadCommand lCommand;
    
    // save current offset, to jump to next LoadCommand.
    uint32_t next_offset = file.tellg();

    // for now only scanning LoadCommands of Type 'Segment'.
    lCommand.setCommand(FileIO::read_u32(file, true));

    uint32_t commandType = lCommand.getCommandType();
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
    } else if (magicBytes_u32 == 0xFEEDFACF) { // x86-64 mach file
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
  
  numLoadCommands_u32 = loadCommand.size();
  // skip to next LCommand structure and code_signature
  //file.seekg( (sizeOfLoadCommand_u32 + 0x24) + std::ios::cur); 

  mapFlagDefinitions();
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

uint32_t LoadCommand::getCommandType() {
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

void MACHO::mapFlagDefinitions() {
  using namespace std;

  magicMap_m.insert(pair<uint32_t, string> (0xFEEDFACE, "MACHO_32"));
  magicMap_m.insert(pair<uint32_t, string> (0xFEEDFACF, "MACHO_64"));
  magicMap_m.insert(pair<uint32_t, string> (0xCAFEBABE, "MACHO_FAT"));
  magicMap_m.insert(pair<uint32_t, string> (0xBEBAFECA, "MACHO_FAT_CIGAM"));

  cputType_m.insert(pair<uint32_t, string> (0x07, "CPU_TYPE_X86"));
  cputType_m.insert(pair<uint32_t, string> (0x01000007, "CPU_TYPE_X64"));
  cputType_m.insert(pair<uint32_t, string> (0x0C, "CPU_TYPE_ARM"));
  cputType_m.insert(pair<uint32_t, string> (0x0100000C, "CPU_TYPE_ARM64"));
  cputType_m.insert(pair<uint32_t, string> (0x12, "CPU_TYPE_PPC"));
  
  headerFileType_m.insert(pair<uint32_t, string> (0x1, "MACH_OBJECT"));
  headerFileType_m.insert(pair<uint32_t, string> (0x2, "MACH_EXECUTE"));
  headerFileType_m.insert(pair<uint32_t, string> (0x3, "MACH_FVMLIB"));
  headerFileType_m.insert(pair<uint32_t, string> (0x4, "MACH_CORE"));
  headerFileType_m.insert(pair<uint32_t, string> (0x5, "MACH_PRELOAD"));
  headerFileType_m.insert(pair<uint32_t, string> (0x6, "MACH_DYLIB"));
  headerFileType_m.insert(pair<uint32_t, string> (0x7, "MACH_DYLINKER"));
  headerFileType_m.insert(pair<uint32_t, string> (0x8, "MACH_BUNDLE"));
  headerFileType_m.insert(pair<uint32_t, string> (0x9, "MACH_DYLIB_STUB"));
  headerFileType_m.insert(pair<uint32_t, string> (0xA, "MACH_DSYM"));
  headerFileType_m.insert(pair<uint32_t, string> (0xB, "MACH_KEXT_BUNDLE"));

  headerFlags_m.insert(pair<uint32_t, string> (0x1, "MACH_NOUNDEFS"));
  headerFlags_m.insert(pair<uint32_t, string> (0x2, "MACH_INCRLINK"));
  headerFlags_m.insert(pair<uint32_t, string> (0x4, "MACH_DYLDLINK"));
  headerFlags_m.insert(pair<uint32_t, string> (0x8, "MACH_BINDATLOAD"));
  headerFlags_m.insert(pair<uint32_t, string> (0x10, "MACH_PREBOUND"));
  headerFlags_m.insert(pair<uint32_t, string> (0x20, "MACH_SPLIT_SEGS"));
  headerFlags_m.insert(pair<uint32_t, string> (0x40, "MACH_LAZY_INIT"));
  headerFlags_m.insert(pair<uint32_t, string> (0x80, "MACH_TWOLEVEL"));
  headerFlags_m.insert(pair<uint32_t, string> (0x100, "MACH_FORCE_FLAT"));
  headerFlags_m.insert(pair<uint32_t, string> (0x200, "MACH_NOMULTIDEFS"));
  headerFlags_m.insert(pair<uint32_t, string> (0x400, "MACH_NOFIXPREBINDING"));
  headerFlags_m.insert(pair<uint32_t, string> (0x800, "MACH_PREBINDABLE"));
  headerFlags_m.insert(pair<uint32_t, string> (0x1000, "MACH_ALLMODSBOUND"));
  headerFlags_m.insert(pair<uint32_t, string> (0x2000, "MACH_SUBSECTIONS_VIA_SYMBOLS"));
  headerFlags_m.insert(pair<uint32_t, string> (0x4000, "MACH_CANONICAL"));
  headerFlags_m.insert(pair<uint32_t, string> (0x8000, "MACH_WEAK_DEFINES"));
  headerFlags_m.insert(pair<uint32_t, string> (0x10000, "MACH_BINDS_TO_WEAK"));
  headerFlags_m.insert(pair<uint32_t, string> (0x20000, "MACH_ALLOW_STACK_EXECUTION"));
  headerFlags_m.insert(pair<uint32_t, string> (0x40000, "MACH_ROOT_SAFE"));
  headerFlags_m.insert(pair<uint32_t, string> (0x80000, "MACH_SETUID_SAFE"));
  headerFlags_m.insert(pair<uint32_t, string> (0x100000, "MACH_NO_REEXPORTED_DYLIBS"));
  headerFlags_m.insert(pair<uint32_t, string> (0x200000, "MACH_PIE"));
  headerFlags_m.insert(pair<uint32_t, string> (0x400000, "MACH_DEAD_STRIPPABLE_DYLIB"));
  headerFlags_m.insert(pair<uint32_t, string> (0x800000, "MACH_HAS_TLV_DESCRIPTORS"));
  headerFlags_m.insert(pair<uint32_t, string> (0x1000000, "MACH_NO_HEAP_EXECUTION"));
  

  loadCommandType_m.insert(pair<uint32_t, string> (0x1, "SEGMENT"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x2, "SYM_TAB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x3, "SYM_SEG"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x4, "THREAD"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x5, "UNIX_THREAD"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x6, "LOAD_FVM_LIB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x7, "ID_FVM_LIB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x8, "IDENT"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x9, "FVM_FILE"));
  loadCommandType_m.insert(pair<uint32_t, string> (0xA, "PREPAGE"));
  loadCommandType_m.insert(pair<uint32_t, string> (0xB, "DY_SYM_TAB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0xC, "LOAD_DYLIB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0xD, "ID_DYLIB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0xE, "LOAD_DYLINKER"));
  loadCommandType_m.insert(pair<uint32_t, string> (0xF, "ID_DYLINKER"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x10, "PREBOUND_DYLIB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x11, "ROUTINES"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x12, "SUB_FRAMEWORK"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x13, "SUB_UMBRELLA"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x14, "SUB_CLIENT"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x15, "SUB_LIBRARY"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x16, "TWOLEVEL_HINTS"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x17, "PREBIND_CKSUM"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x18, "LOAD_WEAK_DYLIB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x19, "SEGMENT_64"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x1A, "ROUTINES_64"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x1B, "UUID"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x1C, "RPATH"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x1D, "CODE_SIGNATURE"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x1E, "SEGMENT_SPLIT_INFO"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x1F, "REEXPORT_DYLIB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x20, "LAZY_LOAD_DYLIB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x21, "ENCRYPTION_INFO"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x22, "DYLD_INFO"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x22, "DYLD_INFO_ONLY"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x23, "LOAD_UPWARD_DYLIB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x24, "VERSION_MIN_MAC_OSX"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x25, "VERSION_MIN_IPHONE_OS"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x26, "FUNCTION_STARTS"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x27, "DYLD_ENVIRONMENT"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x28, "MAIN"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x28, "MAIN_DYLIB"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x29, "DATA_IN_CODE"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x2A, "SOURCE_VERSION"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x2B, "DYLIB_CODE_SIGN_DRS"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x2c, "ENCRYPTION_INFO_64"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x32, "LC_BUILD_VERSION"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x33, "LC_DYLD_EXPORTS_TRIE"));
  loadCommandType_m.insert(pair<uint32_t, string> (0x34, "LC_DYLD_CHAINED_FIXUPS"));

}

void MACHO::printFlag(uint32_t flag, uint32_t value) {
    if (flag == magictypes)
      std::cout << magicMap_m[magicBytes_u32] << std::endl;
  else if (flag == cputypes)
      std::cout << cputType_m[cpuType_u32] << std::endl;
  else if (flag == headerfiltype)
      std::cout << headerFileType_m[fileType_u32] << std::endl;
  else if (flag == headerflags)
      std::cout << this->headerFlags_m[flags_u32] << std::endl;
  else if (flag == loadcommandtype)
      std::cout << this->loadCommandType_m[value] << std::endl;
}

void MACHO::printMach() {
  using namespace std;

  cout << "Mach-O File: \n";
  cout << "  Magic bytes: \t0x" << hex << this->getMagicBytes() << " ";
  printFlag(magictypes, 0);
  cout << "  CPU type:    \t0x" << hex << this->getCputType() << " ";
  printFlag(cputypes, 0);
  cout << "  CPU subtype: \t 0x" << hex << this->getCpuSubType() << endl;
  cout << "  File type:   \t 0x" << hex << this->getFileType() << " ";
  printFlag(headerfiltype, 0);
  cout << "  Number of load commands: \t0x" << hex << this->getNumLoadCommands() << endl;
  cout << "  Size of Load commands:   \t0x" << hex << this->getSizeOfLoadCommand() << endl << endl;

  for(uint32_t idx = 0; idx < numLoadCommands_u32 ; idx++) { 
    cout << " command type: \t" << " ";
    printFlag(loadcommandtype, loadCommand[idx].getCommandType());
    cout << " command size: \t0x" << hex << loadCommand[idx].getCommandSize() << endl;
    cout << " segment name: \t" << loadCommand[idx].getSegmentName() << endl;
    cout << " VM Address:   \t0x" << hex << loadCommand[idx].getVMaddress() << endl;
    cout << " VM Size:      \t0x" << hex <<  loadCommand[idx].getVMSize() << endl;
    cout << " file offset:  \t0x" << hex << loadCommand[idx].getFileOffset() << endl;
    cout << " file size:    \t0x" << hex << loadCommand[idx].getFileSize() << endl << endl;
  }

    //  code directory info
  //  start of section headers

  // Fat mach-O file
  //  magic bytes
  //  fat_arch sections
  //  mach-o header
  //  
}

MACHO::MACHO() {}
MACHO::~MACHO() {}