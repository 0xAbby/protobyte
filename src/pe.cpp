/**
 * @file pe.cpp
 * @brief  Implements functions that deals with PE structures
 *        read and save information in a PE class object members.
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#include "headers.h"

PE::PE() {}
PE::~PE() {
  delete[] dataDir;
  delete[] sections;
}
PE::PE(std::string filename) {
  init(filename);
}

void PE::init(std::string filename) {
  std::ifstream in(filename, std::ios::binary);
  parse(in);
}

/**
 * @brief Given an open file in ifstream, it parses PE header, data directories,
 * and sections. then prints out basic info parsed.
 *
 * @param in An std::ifstream object with PE file already opened,
 * assumption here is that the stream object is at offset 0.
 *
 * @return none.
 */
void PE::parse(std::ifstream& in) {
  // parsing process in steps
  readDOSHeader(in);
  readPE(in);

  dataDir = new DataDirectory[numberOfRvaAndSizes_u32];
  dataDir->readDataDirectory(in, dataDir, numberOfRvaAndSizes_u32);

  sections = new PESection[numberOfSections_u16];
  sections->readSections(in, sections, numberOfSections_u16);

  // print PE info
  using namespace std;
  cout << "Parsed info: \n\n";
  // print magic bytes
  cout << "Magic bytes: 0x" << hex << getDosMagic() << endl;
  // print PE offset
  cout << "PE offset: 0x" << hex << getElfanew() << endl;
  // print number of section
  cout << "Number of sections: " << getNumberOfSections() << endl;
  // print characteristics
  cout << "Characteristics: 0x" << hex << getCharacteristics() << endl << endl;
  // print sections information
  for (int idx = 0; idx < numberOfSections_u16; idx++) {
    cout << "  Name: " << sections[idx].getName() << endl;
    cout << "  Virtual size: 0x" << hex << sections[idx].getVirtualSize()
         << endl;
    cout << "  Virtual Address: 0x" << hex << sections[idx].getVirtualAddress()
         << endl;

    cout << "  Characteristics: 0x" << hex << sections[idx].getCharacteristics()
         << endl;
    cout << endl;
  }
  // mapHeaderFlags();
}

/**
 * @brief Parses Dos header into members of PE class object.
 *
 * @param in An std::ifstream object with PE file already opened,
 * assumption here is that the stream object is at offset 0.
 *
 * @return none.
 */
void PE::readDOSHeader(std::ifstream& in) {
  // Reading DOS Header
  dosMagic_u16 = read_u16(in, true);
  e_cblp_u16 = read_u16(in, true);
  e_cp_u16 = read_u16(in, true);
  e_crlc_u16 = read_u16(in, true);
  e_cparhdr_u16 = read_u16(in, true);
  e_minalloc_u16 = read_u16(in, true);
  e_maxalloc_u16 = read_u16(in, true);
  e_ss_u16 = read_u16(in, true);
  e_sp_u16 = read_u16(in, true);
  e_csum_u16 = read_u16(in, true);
  e_ip_u16 = read_u16(in, true);
  e_cs_u16 = read_u16(in, true);
  e_lfarlc_u16 = read_u16(in, true);
  e_ovno_u16 = read_u16(in, true);
  e_res_u64 = read_u64(in, true);
  e_oemid_u16 = read_u16(in, true);
  e_oeminfo_u16 = read_u16(in, true);
  e_res2_u64 = read_u64(in, true);
  e_res2_u64 = read_u64(in, true);
  e_res2_u64 = read_u32(in, true);
  e_lfanew_u32 = read_u32(in, true);
}

/**
 * @brief Parses PE header into members of PE class object.
 *
 * @param in An std::ifstream object with PE file already opened,
 * e_lfanew needs to have been read correctly for this function to work.
 *
 * @return none.
 */
void PE::readPE(std::ifstream& in) {
  in.seekg(e_lfanew_u32, std::ios_base::beg);

  // PE header
  peSignature_u32 = read_u32(in, true);
  machine_u16 = read_u16(in, true);
  numberOfSections_u16 = read_u16(in, true);
  timeStamp_u32 = read_u32(in, true);
  symTablePtr_u32 = read_u32(in, true);
  numberOfSym_u32 = read_u32(in, true);
  optionalHeaderSize_u16 = read_u16(in, true);
  characteristics_u16 = read_u16(in, true);

  // optional header (Standard Fields)
  optionalHeaderMagic_u16 = read_u16(in, true);
  majorLinkerVer_u8 = read_u8(in);
  minorLinkerVer_u8 = read_u8(in);
  sizeOfCode_u32 = read_u32(in, true);
  sizeOfInitializedData_u32 = read_u32(in, true);
  sizeOfUninitializedData_u32 = read_u32(in, true);
  entryPoint_u32 = read_u32(in, true);
  baseOfCode_u32 = read_u32(in, true);

  if (optionalHeaderMagic_u16 == OPTIONAL_IMAGE_PE32_plus) {
    imageBase_u64 = read_u64(in, true);
    // std::cout << "64bit PE \n";
  } else {
    //  std::cout << "32bit PE\n";
    baseOfData_u32 = read_u32(in, true);
    imageBase_u64 = read_u32(in, true);
  }
  sectionAlignment_u32 = read_u32(in, true);
  fileAlignment_u32 = read_u32(in, true);
  majorOSVersion_u16 = read_u16(in, true);
  minorOSVersion_u16 = read_u16(in, true);
  majorImageVersion_u16 = read_u16(in, true);
  minorImageVersion_u16 = read_u16(in, true);
  majorSubsystemVersion_u16 = read_u16(in, true);
  minorSubsystemVer_u16 = read_u16(in, true);
  win32VersionVal_u32 = read_u32(in, true);
  sizeOfImage_u32 = read_u32(in, true);
  sizeOfHeaders_u32 = read_u32(in, true);
  checkSum_u32 = read_u32(in, true);
  subsystem_u16 = read_u16(in, true);
  dllCharacteristics_u16 = read_u16(in, true);

  if (optionalHeaderMagic_u16 == OPTIONAL_IMAGE_PE32_plus) {
    sizeOfStackReserve_u64 = read_u64(in, true);
    sizeOfStackCommit_u64 = read_u64(in, true);
    sizeOfHeapReserve_u64 = read_u64(in, true);
    sizeOfHeapCommit_u64 = read_u64(in, true);
  } else {
    sizeOfStackReserve_u64 = read_u32(in, true);
    sizeOfStackCommit_u64 = read_u32(in, true);
    sizeOfHeapReserve_u64 = read_u32(in, true);
    sizeOfHeapCommit_u64 = read_u32(in, true);
  }
  loaderFlags_u32 = read_u32(in, true);
  numberOfRvaAndSizes_u32 = read_u32(in, true);
}

/**
 * @brief Parses PE sections into members of PE class object.
 *
 * @param in An std::ifstream object with PE file already opened,
 * this functions assumes file stream is the proper
 * offset before this function is called.
 * @param sections an array of sections that has been already allocated
 *  based on info read from PE header previously.
 *
 * @return none.
 */
void PESection::readSections(std::ifstream& in,
                             PESection sections[],
                             uint32_t number) {
  numberOfSections_u32 = number;
  for (uint32_t idx = 0; idx < numberOfSections_u32; idx++) {
    sections[idx].setName(in);
    sections[idx].setVirtualSize(read_u32(in, true));
    sections[idx].setVirtualAddress(read_u32(in, true));
    sections[idx].setRawDataSize(read_u32(in, true));
    sections[idx].setRawDataPointer(read_u32(in, true));
    sections[idx].setPointerToRelocations(read_u32(in, true));
    sections[idx].setPointerToLinenumbers(read_u32(in, true));
    sections[idx].setNumberOfRelocations(read_u16(in, true));
    sections[idx].setNumberOfLineNumbers(read_u16(in, true));
    sections[idx].setCharacteristics(read_u32(in, true));
  }
}

/**
 * @brief Parses PE data directories into members of PE class object.
 *
 * @param in An std::ifstream object with PE file already opened,
 * this functions assumes file stream is the proper
 * offset before this function is called.
 * @param dataDirectory an array of directories that has been
 * already allocated based on info read from PE header previously.
 *
 * @return none.
 */
void DataDirectory::readDataDirectory(std::ifstream& in,
                                      DataDirectory dataDirectory[],
                                      uint32_t number) {
  // Reading Data Directories
  numberOfRva_u32 = number;
  for (uint32_t idx = 0; idx < numberOfRva_u32; idx++) {
    dataDirectory[idx].setVirtualAddress(read_u32(in, true));
    dataDirectory[idx].setSize(read_u32(in, true));
    // setting directory offset is possible after sections info is read.
  }
}

/**
 * @brief Maps PE flag and property values into map object.
 *
 * @return none.
 */
void PE::mapHeaderFlags() {
  using namespace std;
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00000008, "IMAGE_SCN_TYPE_NO_PAD"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00000020, "IMAGE_SCN_CNT_CODE"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_ DATA"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00000100, "IMAGE_SCN_LNK_OTHER"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00000200, "IMAGE_SCN_LNK_INFO"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00000800, "IMAGE_SCN_LNK_REMOVE"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00001000, "IMAGE_SCN_LNK_COMDAT"));
  mapSectionFlags.insert(pair<uint32_t, string>(0x00008000, "IMAGE_SCN_GPREL"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00020000, "IMAGE_SCN_MEM_PURGEABLE"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00020000, "IMAGE_SCN_MEM_16BIT"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00040000, "IMAGE_SCN_MEM_LOCKED"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00080000, "IMAGE_SCN_MEM_PRELOAD"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00100000, "IMAGE_SCN_ALIGN_1BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00200000, "IMAGE_SCN_ALIGN_2BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00300000, "IMAGE_SCN_ALIGN_4BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00400000, "IMAGE_SCN_ALIGN_8BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00500000, "IMAGE_SCN_ALIGN_16BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00600000, "IMAGE_SCN_ALIGN_32BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00700000, "IMAGE_SCN_ALIGN_64BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00800000, "IMAGE_SCN_ALIGN_128BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00900000, "IMAGE_SCN_ALIGN_256BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00A00000, "IMAGE_SCN_ALIGN_512BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00B00000, "IMAGE_SCN_ALIGN_1024BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00C00000, "IMAGE_SCN_ALIGN_2048BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00D00000, "IMAGE_SCN_ALIGN_4096BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x00E00000, "IMAGE_SCN_ALIGN_8192BYTES"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x01000000, "IMAGE_SCN_LNK_NRELOC_OVFL"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x02000000, "IMAGE_SCN_MEM_DISCARDABLE"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x04000000, "IMAGE_SCN_MEM_NOT_CACHED"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x08000000, "IMAGE_SCN_MEM_NOT_PAGED"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x10000000, "IMAGE_SCN_MEM_SHARED"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x20000000, "IMAGE_SCN_MEM_EXECUTE"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x40000000, "IMAGE_SCN_MEM_READ"));
  mapSectionFlags.insert(
      pair<uint32_t, string>(0x80000000, "IMAGE_SCN_MEM_WRITE"));

  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x0001, "IMAGE_FILE_RELOCS_STRIPPED"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"));
  mapPEFlagTypes.insert(pair<uint16_t, string>(
      0x0010, "IMAGmapPEFlagTypes.E_FILE_AGGRESSIVE_WS_TRIM"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x0080, "IMAGE_FILE_BYTES_REVERSED_LO"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x0100, "IMAGE_FILE_32BIT_MACHINE"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x0200, "IMAGE_FILE_DEBUG_STRIPPED"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP"));
  mapPEFlagTypes.insert(pair<uint16_t, string>(0x1000, "IMAGE_FILE_SYSTEM"));
  mapPEFlagTypes.insert(pair<uint16_t, string>(0x2000, "IMAGE_FILE_DLL"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY"));
  mapPEFlagTypes.insert(
      pair<uint16_t, string>(0x8000, "IMAGE_FILE_BYTES_REVERSED_HI"));

  mapImageCharacteristics.insert(pair<uint16_t, string>(
      0x0020, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"));
  mapImageCharacteristics.insert(
      pair<uint16_t, string>(0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"));
  mapImageCharacteristics.insert(pair<uint16_t, string>(
      0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"));
  mapImageCharacteristics.insert(
      pair<uint16_t, string>(0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"));
  mapImageCharacteristics.insert(
      pair<uint16_t, string>(0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"));
  mapImageCharacteristics.insert(
      pair<uint16_t, string>(0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH"));
  mapImageCharacteristics.insert(
      pair<uint16_t, string>(0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND"));
  mapImageCharacteristics.insert(
      pair<uint16_t, string>(0x1000, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER"));
  mapImageCharacteristics.insert(
      pair<uint16_t, string>(0x2000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"));
  mapImageCharacteristics.insert(
      pair<uint16_t, string>(0x4000, "IMAGE_DLLCHARACTERISTICS_GUARD_CF"));
  mapImageCharacteristics.insert(pair<uint16_t, string>(
      0x8000, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"));

  mapMachineType.insert(
      pair<uint16_t, string>(0x0, "IMAGE_FILE_MACHINE_UNKNOWN"));
  mapMachineType.insert(
      pair<uint16_t, string>(0x200, "IMAGE_FILE_MACHINE_IA64"));
  mapMachineType.insert(
      pair<uint16_t, string>(0x14c, "IMAGE_FILE_MACHINE_I386"));
  mapMachineType.insert(
      pair<uint16_t, string>(0x8664, "IMAGE_FILE_MACHINE_AMD64"));
  mapMachineType.insert(
      pair<uint16_t, string>(0x1c0, "IMAGE_FILE_MACHINE_ARM"));
  mapMachineType.insert(
      pair<uint16_t, string>(0xaa64, "IMAGE_FILE_MACHINE_ARM64"));
  mapMachineType.insert(
      pair<uint16_t, string>(0x1c4, "IMAGE_FILE_MACHINE_ARMNT"));
  mapMachineType.insert(
      pair<uint16_t, string>(0xebc, "IMAGE_FILE_MACHINE_EBC"));

  mapImageSubsystem.insert(pair<uint8_t, string>(0, "IMAGE_SUBSYSTEM_UNKNOWN"));
  mapImageSubsystem.insert(pair<uint8_t, string>(1, "IMAGE_SUBSYSTEM_NATIVE"));
  mapImageSubsystem.insert(
      pair<uint8_t, string>(2, "IMAGE_SUBSYSTEM_WINDOWS_GUI"));
  mapImageSubsystem.insert(
      pair<uint8_t, string>(3, "IMAGE_SUBSYSTEM_WINDOWS_CUI"));

  mapImageSubsystem.insert(pair<uint8_t, string>(5, "IMAGE_SUBSYSTEM_OS2_CUI"));
  mapImageSubsystem.insert(
      pair<uint8_t, string>(7, "IMAGE_SUBSYSTEM_POSIX_CUI"));
  mapImageSubsystem.insert(
      pair<uint8_t, string>(8, "IMAGE_SUBSYSTEM_NATIVE_WINDOWS"));
  mapImageSubsystem.insert(
      pair<uint8_t, string>(9, "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"));
  mapImageSubsystem.insert(
      pair<uint8_t, string>(10, "IMAGE_SUBSYSTEM_EFI_APPLICATION"));
  mapImageSubsystem.insert(
      pair<uint8_t, string>(11, "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"));
  mapImageSubsystem.insert(
      pair<uint8_t, string>(12, "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"));
  mapImageSubsystem.insert(
      pair<uint8_t, string>(13, "IMAGE_SUBSYSTEM_EFI_ROM"));
  mapImageSubsystem.insert(pair<uint8_t, string>(14, "IMAGE_SUBSYSTEM_XBOX"));
  mapImageSubsystem.insert(
      pair<uint8_t, string>(16, "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"));
}

uint16_t PE::getDosMagic() const {
  return this->dosMagic_u16;
}
uint16_t PE::getSections() const {
  return this->numberOfSections_u16;
}
uint32_t PE::getElfanew() const {
  return this->e_lfanew_u32;
}
uint32_t PE::getPESignature() const {
  return this->peSignature_u32;
}
uint16_t PE::getNumberOfSections() const {
  return this->numberOfSections_u16;
}
uint16_t PE::getMachineType() const {
  return this->machine_u16;
}
uint16_t PE::getCharacteristics() const {
  return this->characteristics_u16;
}
uint16_t PE::getDllCharacterics() const {
  return this->dllCharacteristics_u16;
}
uint32_t PE::getChecksum() const {
  return this->checkSum_u32;
}
uint32_t PE::getBaseOfCode() const {
  return this->baseOfCode_u32;
}
uint32_t PE::getSectionAlignment() const {
  return this->sectionAlignment_u32;
}
uint32_t PE::getnumberOfRvaAndSizes() const {
  return this->numberOfRvaAndSizes_u32;
}
uint64_t PE::getImageBase() const {
  return this->imageBase_u64;
}
PESection PE::getSection(uint16_t sec) const {
  return this->sections[sec];
}

void DataDirectory::setOffset(uint32_t offset) {
  this->offset = offset;
}
void DataDirectory::setVirtualAddress(uint32_t va) {
  this->virtualAddr = va;
}
void DataDirectory::setSize(uint32_t sz) {
  this->size = sz;
}

auto DataDirectory::getOffset() const {
  return this->offset;
}
auto DataDirectory::getVA() const {
  return this->virtualAddr;
}
auto DataDirectory::getSize() const {
  return this->size;
}