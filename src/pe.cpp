// pe.cpp:
//    implements functions that deals with PE structures
//    read PE and save information in a struct
//
//  https://github.com/0xAbby/binlyzer
//
// Author:
//  Abdullah Ada (0xabby)
//
#include "pe.h"

void PE::parse(std::ifstream &in) {
  // parsing process in steps
  readDOSHeader(in);
  readPE(in);
  DataDir dataDir[numberOfRvaAndSizes];
  readDatadir(in, dataDir);
 // readSections(in);
}
PE::~PE() {

}

void PE::readDOSHeader(std::ifstream &in) {
  
  // Reading DOS Header
  dosMagic = read16_le(in);
  e_cblp = read16_le(in);
  e_cp = read16_le(in);
  e_crlc = read16_le(in);
   e_cparhdr = read16_le(in);
  e_minalloc = read16_le(in);
  e_maxalloc = read16_le(in);
  e_ss = read16_le(in);
  e_sp = read16_le(in);
  e_csum = read16_le(in);
  e_ip = read16_le(in);
  e_cs = read16_le(in);
  e_lfarlc = read16_le(in);
  e_ovno = read16_le(in);
  e_res = read64_le(in);
  e_oemid = read16_le(in);
  e_oeminfo = read16_le(in);
  e_res2 = read64_le(in);
  e_res2 = read64_le(in);
  e_res2 = read32_le(in);
  e_lfanew = read32_le(in);
}

uint8_t read8_le(std::ifstream &in) {
  uint8_t value = 0;
  char ch[1] = {0};

  in.read(ch, 1);
  value = ch[0];
  
  return value;
}

uint16_t read16_le(std::ifstream &in) {
  uint16_t value = 0;
  char ch[3] = {0};

  in.read(ch, 2);
  value = ch[0];
  value |= ch[1] << 8;
  
  return value;
}

uint32_t read32_le(std::ifstream &in) {
  uint32_t value = 0;
  char ch[5] = {0};

  in.read(ch, 4);
  value = ch[0];
  value |= ch[1] << 8;
  value |= ch[2] << 16;
  value |= ch[3] << 24;
  
  return value;
}

uint64_t read64_le(std::ifstream &in) {
  uint64_t value = 0;
  char ch[9] = {0};

  in.read(ch, 8);
  value = ch[0];
  value |= ch[1] << 8;
  value |= ch[2] << 16;
  value |= ch[3] << 24;
  value |= ch[4] << 32;
  value |= ch[5] << 40;
  value |= ch[6] << 48;
  value |= ch[7] << 54;
  
  return value;
}

void PE::readPE(std::ifstream &in) {
  in.seekg(e_lfanew, std::ios_base::beg);

  // PE header
  peSignature = read32_le(in);
  machine = read16_le(in);
  numberOfSections = read16_le(in);
  timeStamp = read32_le(in);
  symTablePtr = read32_le(in);
  numberOfSym = read32_le(in);
  optionalHeaderSize = read16_le(in);
  characteristics = read16_le(in);

  // optional header (Standard Fields)
  optHeaderMagic = read16_le(in);
  majorLinkerVer = read8_le(in);
  minorLinkerVer = read8_le(in);
  sizeOfCode = read32_le(in);
  sizeOfInitializedData = read32_le(in);
  sizeOfUninitializedData = read32_le(in);
  entryPoint = read32_le(in);
  baseOfCode = read32_le(in);

  if (optHeaderMagic == OPTIONAL_IMAGE_PE32_plus) {
    imageBase = read64_le(in); 
  } else {
    baseOfData = read32_le(in);
    imageBase = read32_le(in); 
  }
  sectionAlignment = read32_le(in);
  fileAlignment = read32_le(in);
  majorOSVer = read16_le(in);
  minorOSVer = read16_le(in);
  majorImageVer = read16_le(in);
  minorImageVer = read16_le(in);
  majorSubsystemVer = read16_le(in);
  minorSubsystemVer = read16_le(in);
  win32VersionVal = read32_le(in);
  sizeOfImage = read32_le(in);
  sizeOfHeaders = read32_le(in);
  checkSum = read32_le(in);
  subsystem = read16_le(in);
  dllCharacteristics = read16_le(in);

  if (optHeaderMagic == OPTIONAL_IMAGE_PE32_plus) {
    sizeOfStackReserve = read64_le(in);
    sizeOfStackCommit = read64_le(in);
    sizeOfHeapReserve = read64_le(in);
    sizeOfHeapCommit = read64_le(in);
  } else {
    sizeOfStackReserve = read32_le(in);
    sizeOfStackCommit = read32_le(in);
    sizeOfHeapReserve = read32_le(in);
    sizeOfHeapCommit = read32_le(in);
  }
  loaderFlags = read32_le(in);
  numberOfRvaAndSizes = read32_le(in);
}

// uint64_t rva_to_offset(int numberOfSections, uint64_t rva, 
//                            section_table_t *sections) {
//   if(rva == 0) return 0;
//   uint64_t sumAddr;

//   for(int idx = 0; idx < numberOfSections; idx++) 
//   {
//     sumAddr = sections[idx].virtualAddr + sections[idx].sizeOfRawData;
//     if(rva >= sections[idx].virtualAddr && (rva <= sumAddr)) {
//       return  sections[idx].ptrToRawData + (rva - sections[idx].virtualAddr);
//     }
//   }
//   return -1;
// }

void PE::readDatadir(std::ifstream &in, DataDir dataDir[]) {
  // Reading Data Directories
  for (uint32_t idx = 0; idx < numberOfRvaAndSizes; idx++) {
    dataDir[idx].setVA(read32_le(in));
    dataDir[idx].setSize(read32_le(in));
    dataDir[idx].setOffset(0);  // setting file offset is 
                                // possible after sections info is read.
  }
}

// void PE::readSections(std::fstream in) {
//   // Reading Sections data

//   Section sec[numberOfSections];

//   for (int idx = 0; idx < numberOfSections; idx++) {
//     sec[idx].setName(in.read(8));
//     sec[idx].setVSize(in.read(); // 32 bits);
//     sec[idx].setVA(in.read(); // 32 bits);
//     sec[idx].setRawDataSz(in.read(); // 32 bits);
//     sec[idx].setRawDataPtr(in.read(); // 32 bits);
//     sec[idx].setPtrReloc(in.read(); // 32 bits);
//     sec[idx].setPtrLineNum(in.read(); // 32 bits);
//     sec[idx].setRelocNum(in.read(); // 16 bits);
//     sec[idx].setLineNum(in.read(); // 16 bits);
//     sec[idx].setCharacter(in.read(); // 32 bits);
//   }
// }



// char *PE::read_str(std::ifstream &in, int count) {
//   char *ch_ptr = (char*) malloc(sizeof(char)*count);
//   for(int i = 0; i < count; i++) {
//     ch_ptr[i] = fgetc(in);
//   }
//   ch_ptr[strlen(ch_ptr)] = 0;
//   return ch_ptr;
// }
