// pe.cpp:
//    implements functions that deals with PE structures
//    read PE and save information in a struct
//
//  https://github.com/0xAbby/binlyzer
//
// Author:
//  Abdullah Ada (0xabby)
//
#include "headers.h"

void PE::parse(std::ifstream& in) {
  // parsing process in steps
  readDOSHeader(in);
  readPE(in);
  
  dataDir = new DataDir[numberOfRvaAndSizes_u32];
  readDatadir(in, dataDir);

  sections = new Section[numberOfSections_u16];
  readSections(in, sections);

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
  for (int idx = 0; idx < numberOfSections_u16; idx++){
    cout << "  Name: " << sections[idx].getName() << endl;
    cout << "  Virtual size: 0x" << hex << sections[idx].getVirtualSize() << endl;
    cout << "  Virtual Address: 0x" << hex << sections[idx].getVirtualAddress() << endl;

    cout << "  Characteristics: 0x" << hex << sections[idx].getCharacteristics() << endl;
    cout << endl;
  }
  // mapHeaderFlags();
}
PE::~PE() {
    delete[] dataDir;
    delete[] sections;
}

void PE::readDOSHeader(std::ifstream& in) {
  // Reading DOS Header
  dosMagic_u16 = read16_le(in);
  e_cblp_u16 = read16_le(in);
  e_cp_u16 = read16_le(in);
  e_crlc_u16 = read16_le(in);
  e_cparhdr_u16 = read16_le(in);
  e_minalloc_u16 = read16_le(in);
  e_maxalloc_u16 = read16_le(in);
  e_ss_u16 = read16_le(in);
  e_sp_u16 = read16_le(in);
  e_csum_u16 = read16_le(in);
  e_ip_u16 = read16_le(in);
  e_cs_u16 = read16_le(in);
  e_lfarlc_u16 = read16_le(in);
  e_ovno_u16 = read16_le(in);
  e_res_u64 = read64_le(in);
  e_oemid_u16 = read16_le(in);
  e_oeminfo_u16 = read16_le(in);
  e_res2_u64 = read64_le(in);
  e_res2_u64 = read64_le(in);
  e_res2_u64 = read32_le(in);
  e_lfanew_u32 = read32_le(in);
}

uint8_t read8_le(std::ifstream& in) {
  uint8_t value = 0;
  unsigned char ch[1] = {0};

  in.read(reinterpret_cast<char*>(ch), 1);
  value = ch[0];

  return value;
}

uint16_t read16_le(std::ifstream& in) {
  uint16_t value = 0;
  unsigned char ch[3] = {0};

  in.read(reinterpret_cast<char*>(ch), 2);
  value =  ch[0];
  value |= uint16_t( ch[1]) << 8;

  return value;
}

uint32_t read32_le(std::ifstream& in) {
  uint32_t value = 0;
  unsigned char ch[4] = {0};

  in.read(reinterpret_cast<char*>(ch), 4);
  value =  ch[0];
  value |= uint32_t(ch[1]) << 8;
  value |= uint32_t(ch[2]) << 16;
  value |= uint32_t(ch[3]) << 24;

  return value;
}

uint64_t read_le(std::ifstream& in, int count) {
    uint64_t value = 0; 
    unsigned char ch[1] = {0};

    for(int idx = 0; idx < count; idx++) {
      in.read(reinterpret_cast<char*>(ch), 1);
      value <<= 8;
      value |= uint8_t(ch[0]);
    }
    
    if (count == 1) return uint8_t(value);
    if (count == 2) return uint16_t(value);
    if (count == 4) return uint32_t(value);
    if (count == 8) return uint64_t(value);
    return value;
  }

uint64_t read64_le(std::ifstream& in) {
  uint64_t value = 0;
  unsigned char ch[9] = {0};

  in.read(reinterpret_cast<char*>(ch), 8);
  value = ch[0];
  value |= uint64_t(ch[1]) << 8;
  value |= uint64_t(ch[2]) << 16;
  value |= uint64_t(ch[3]) << 24;
  value |= uint64_t(ch[4]) << 32;
  value |= uint64_t(ch[5]) << 40;
  value |= uint64_t(ch[6]) << 48;
  value |= uint64_t(ch[7]) << 54;

  return value;
}


uint32_t read32_be(std::ifstream& in) {
  uint32_t value = 0;
  char ch[4] = {0};

  in.read(ch, 4);
  value  = ch[3];
  value |= uint32_t(ch[2]) << 8;
  value |= uint32_t(ch[1]) << 16;
  value |= uint32_t(ch[0]) << 24;

  return value;
}

void PE::readPE(std::ifstream& in) {
  in.seekg(e_lfanew_u32, std::ios_base::beg);

  // PE header
  peSignature_u32 = read32_le(in);
  machine_u16 = read16_le(in);
  numberOfSections_u16 = read16_le(in);
  timeStamp_u32 = read32_le(in);
  symTablePtr_u32 = read32_le(in);
  numberOfSym_u32 = read32_le(in);
  optionalHeaderSize_u16 = read16_le(in);
  characteristics_u16 = read16_le(in);

  // optional header (Standard Fields)
  optionalHeaderMagic_u16 = read16_le(in);
  majorLinkerVer_u8 = read8_le(in);
  minorLinkerVer_u8 = read8_le(in);
  sizeOfCode_u32 = read32_le(in);
  sizeOfInitializedData_u32 = read32_le(in);
  sizeOfUninitializedData_u32 = read32_le(in);
  entryPoint_u32 = read32_le(in);
  baseOfCode_u32 = read32_le(in);

  if (optionalHeaderMagic_u16 == OPTIONAL_IMAGE_PE32_plus) {
    imageBase_u64 = read64_le(in);
    // std::cout << "64bit PE \n";
  } else {
    //  std::cout << "32bit PE\n";
    baseOfData_u32 = read32_le(in);
    imageBase_u64 = read32_le(in);
  }
  sectionAlignment_u32 = read32_le(in);
  fileAlignment_u32 = read32_le(in);
  majorOSVersion_u16 = read16_le(in);
  minorOSVersion_u16 = read16_le(in);
  majorImageVersion_u16 = read16_le(in);
  minorImageVersion_u16 = read16_le(in);
  majorSubsystemVersion_u16 = read16_le(in);
  minorSubsystemVer_u16 = read16_le(in);
  win32VersionVal_u32 = read32_le(in);
  sizeOfImage_u32 = read32_le(in);
  sizeOfHeaders_u32 = read32_le(in);
  checkSum_u32 = read32_le(in);
  subsystem_u16 = read16_le(in);
  dllCharacteristics_u16 = read16_le(in);

  if (optionalHeaderMagic_u16 == OPTIONAL_IMAGE_PE32_plus) {
    sizeOfStackReserve_u64 = read64_le(in);
    sizeOfStackCommit_u64 = read64_le(in);
    sizeOfHeapReserve_u64 = read64_le(in);
    sizeOfHeapCommit_u64 = read64_le(in);
  } else {
    sizeOfStackReserve_u64 = read32_le(in);
    sizeOfStackCommit_u64 = read32_le(in);
    sizeOfHeapReserve_u64 = read32_le(in);
    sizeOfHeapCommit_u64 = read32_le(in);
  }
  loaderFlags_u32 = read32_le(in);
  numberOfRvaAndSizes_u32 = read32_le(in);
}

void PE::readSections(std::ifstream& in, Section sections[]) {
    
  for (int idx = 0; idx < numberOfSections_u16; idx++) {
    sections[idx].setName(in);
    sections[idx].setVirtualSize(read32_le(in));
    sections[idx].setVirtualAddress(read32_le(in));
    sections[idx].setRawDataSize(read32_le(in));
    sections[idx].setRawDataPointer(read32_le(in));
    sections[idx].setPointerToRelocations(read32_le(in));
    sections[idx].setPointerToLinenumbers(read32_le(in));
    sections[idx].setNumberOfRelocations(read16_le(in));
    sections[idx].setNumberOfLineNumbers(read16_le(in));
    sections[idx].setCharacteristics(read32_le(in));
  }
}


void PE::readDatadir(std::ifstream& in, DataDir dataDirectory[]) {
  // Reading Data Directories
  for (uint32_t idx = 0; idx < numberOfRvaAndSizes_u32; idx++) {
    dataDirectory[idx].setVirtualAddress(read32_le(in));
    dataDirectory[idx].setSize(read32_le(in));
    // setting directory offset is possible after sections info is read.
  }
}


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