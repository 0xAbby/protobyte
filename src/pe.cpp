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

void PE::parse(FILE* in) {
  // parsing process in steps
  readDOSHeader(in);
  readPE(in);
  if (peSignature != 0x4550) {
    printf("invalid PE signature.\n");
    return;
  }

  readDatadir(in);
  readSections(in);
}

void PE::readDOSHeader(FILE* in) {
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

void PE::readPE(FILE* in) {
  if (fseek(in, e_lfanew, SEEK_SET) == -1) {
    printf("Error during file reading.\n");
    exit(-1);
  }

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

void PE::readDatadir(FILE* in) {
  DataDir dataDir[numberOfRvaAndSizes];

  // Reading Data Directories
  for (int idx = 0; idx < numberOfRvaAndSizes; idx++) {
    dataDir[idx].setVA(read32_le(in));
    dataDir[idx].setSize(read32_le(in));
    dataDir[idx].setOffset(0);  // need to calculate file offset from VA.
  }
}

void PE::readSections(FILE* in) {
  // Reading Sections data

  Section sec[numberOfSections];

  for (int idx = 0; idx < numberOfSections; idx++) {
    sec[idx].setName(read_str(in, 8));
    sec[idx].setVSize(read32_le(in));
    sec[idx].setVA(read32_le(in));
    sec[idx].setRawDataSz(read32_le(in));
    sec[idx].setRawDataPtr(read32_le(in));
    sec[idx].setPtrReloc(read32_le(in));
    sec[idx].setPtrLineNum(read32_le(in));
    sec[idx].setRelocNum(read16_le(in));
    sec[idx].setLineNum(read16_le(in));
    sec[idx].setCharacter(read32_le(in));
  }
}