/**
 * @file pe.h
 * @brief  Definitions and declarations for PE module.
 *
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#ifndef PE_H
#define PE_H

#include "headers.h"

// PE image type
#define OPTIONAL_IMAGE_PE32 0x10b
#define OPTIONAL_IMAGE_PE32_plus 0x20b

/**
 * @brief holds information for Data directories in a PE file format
 *  such as Import table, export table, IAT table...etc.
 *
 */
class DataDirectory {
 public:
  DataDirectory() {}
  ~DataDirectory() {}

  void setOffset(uint32_t offset);
  void setVirtualAddress(uint32_t va);
  void setSize(uint32_t sz);
  void readDataDirectory(std::ifstream& in,
                         DataDirectory dataDir[],
                         uint32_t number);

  auto getOffset() const;
  auto getVA() const;
  auto getSize() const;

 private:
  // Data Directory
  uint64_t offset;
  uint32_t virtualAddr;
  uint32_t size;
  uint32_t numberOfRva_u32;
};

/**
 * @brief holds information for PE sections in a PE file format
 *  such as .text, .data, .rdata and so on.
 *
 */
class PESection {
 public:
  PESection() {}
  ~PESection() {}

  void readSections(std::ifstream& in, PESection sections[], uint32_t number);

  void setName(std::ifstream& in) {
    for (int idx = 0; idx < 8; idx++)
      name.insert(idx, 1, in.get());
  }
  void setVirtualSize(uint32_t vsz) { this->virtualSize_u32 = vsz; }
  void setVirtualAddress(uint32_t va) { this->virtualAddr_u32 = va; }
  void setRawDataSize(uint32_t sz) { this->sizeOfRawData_u32 = sz; }
  void setRawDataPointer(uint32_t ptr) { this->pointerToRawData_u32 = ptr; }
  void setPointerToRelocations(uint32_t ptr) {
    this->pointerToRelocations_u32 = ptr;
  }
  void setPointerToLinenumbers(uint32_t ptr) {
    this->pointerToLinenumbers_u32 = ptr;
  }
  void setNumberOfRelocations(uint16_t n) { this->numberOfRelocations_u16 = n; }
  void setNumberOfLineNumbers(uint16_t n) { this->numberOfLineNumbers_u16 = n; }
  void setCharacteristics(uint32_t ch) { this->characteristics_u32 = ch; }

  std::string getName() { return this->name; }
  auto getVirtualSize() const { return virtualSize_u32; }
  auto getVirtualAddress() const { return virtualAddr_u32; }
  auto getCharacteristics() const { return characteristics_u32; }

 private:
  // section table
  std::string name;
  uint32_t virtualSize_u32;
  uint32_t virtualAddr_u32;
  uint32_t sizeOfRawData_u32;
  uint32_t pointerToRawData_u32;
  uint32_t pointerToRelocations_u32;
  uint32_t pointerToLinenumbers_u32;
  uint16_t numberOfRelocations_u16;
  uint16_t numberOfLineNumbers_u16;
  uint32_t characteristics_u32;
  uint32_t numberOfSections_u32;
};

class ImportDirectory {
 public:
  ImportDirectory();
  ~ImportDirectory();

 private:
  uint32_t importLookupTableRVA_u32;
  uint32_t timeStamp_u32;
  uint32_t forwarderChain_u32;
  uint32_t nameRVA_u32;
  uint32_t importAddressRVA_u32;
};

class ExportDirectory {
 public:
  ExportDirectory();
  ~ExportDirectory();

 private:
  uint32_t exportFlags_u32;  // Reserved.
  uint32_t timeStamp_u32;    // time/date that the export data was created
  uint16_t majorVersion_u16;
  uint16_t minorVersion_u16;
  uint32_t nameRVA_u32;      // Address of ASCII string to name of the DLL
  uint32_t ordinalBase_u32;  // The starting ordinal number for exports in
                             // this image. This field specifies the
                             // starting ordinal number for the export
                             // address table.

  uint32_t addressTableEntries_u32;  // The number of entries in the
                                     // export address table.
  uint32_t numberOfNamePointers_u32;
  uint32_t
      exportAddressTableRVA_u32;  // The address of the export address table,
  uint32_t namePointerRVA_u32;
  uint32_t ordinalTableRVA_u32;
  //  export_address_name_t *exportAddr_name_t;
};

/**
 * @brief holds information for PE file format, carries out PE-format specific
 * operations, loading, reading displaying header info.
 * @see https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 */
class PE {
 public:
  PE();
  PE(std::string filename);
  ~PE();
  void init(std::string filename);
  void parse(std::ifstream& in);
  void readDOSHeader(std::ifstream& in);
  void readPE(std::ifstream& in);
  void mapHeaderFlags();

  uint16_t getDosMagic() const;
  uint16_t getSections() const;
  uint32_t getElfanew() const;
  uint32_t getPESignature() const;
  uint16_t getNumberOfSections() const;
  uint16_t getMachineType() const;
  uint16_t getCharacteristics() const;
  uint16_t getDllCharacterics() const;
  uint32_t getChecksum() const;
  uint32_t getBaseOfCode() const;
  uint32_t getSectionAlignment() const;
  uint32_t getnumberOfRvaAndSizes() const;
  uint64_t getImageBase() const;
  PESection getSection(uint16_t sec) const;

 private:
  // DOS header
  uint16_t dosMagic_u16;    // Magic DOS signature MZ
  uint16_t e_cblp_u16;      // Bytes on last page of file
  uint16_t e_cp_u16;        // Pages in file
  uint16_t e_crlc_u16;      // Relocations
  uint16_t e_cparhdr_u16;   // Size of header in paragraphs
  uint16_t e_minalloc_u16;  // Minimum extra paragraphs needed
  uint16_t e_maxalloc_u16;  // Maximum extra paragraphs needed
  uint16_t e_ss_u16;        // nitial (relative) SS value
  uint16_t e_sp_u16;        // Initial SP value
  uint16_t e_csum_u16;      // Checksum
  uint16_t e_ip_u16;        // Initial IP value
  uint16_t e_cs_u16;        // Initial (relative) CS value
  uint16_t e_lfarlc_u16;    // File address of relocation table
  uint16_t e_ovno_u16;      // Overloay number
  uint64_t e_res_u64;       // Reserved uint16_ts (4 uint16_ts)
  uint16_t e_oemid_u16;     // OEM identifier (for e_oeminfo)
  uint16_t e_oeminfo_u16;   // OEM information; e_oemid specific
  uint64_t e_res2_u64;      // Reserved uint16_ts (10 uint16_ts)
  uint32_t e_lfanew_u32;    // Offset to start of PE header

  // PE header
  uint32_t peOffset_u32;
  uint32_t peSignature_u32;
  uint16_t machine_u16;
  uint16_t numberOfSections_u16;
  uint32_t timeStamp_u32;
  uint32_t symTablePtr_u32;
  uint32_t numberOfSym_u32;
  uint16_t optionalHeaderSize_u16;
  uint16_t characteristics_u16;

  // Optional Header Image
  uint16_t optionalHeaderMagic_u16;
  uint8_t majorLinkerVer_u8;
  uint8_t minorLinkerVer_u8;
  uint32_t sizeOfCode_u32;
  uint32_t sizeOfInitializedData_u32;
  uint32_t sizeOfUninitializedData_u32;
  uint32_t entryPoint_u32;
  uint32_t baseOfCode_u32;
  uint32_t baseOfData_u32;
  uint64_t imageBase_u64;
  uint32_t sectionAlignment_u32;
  uint32_t fileAlignment_u32;
  uint16_t majorOSVersion_u16;
  uint16_t minorOSVersion_u16;
  uint16_t majorImageVersion_u16;
  uint16_t minorImageVersion_u16;
  uint16_t majorSubsystemVersion_u16;
  uint16_t minorSubsystemVer_u16;
  uint32_t win32VersionVal_u32;
  uint32_t sizeOfImage_u32;
  uint32_t sizeOfHeaders_u32;
  uint32_t checkSum_u32;
  uint16_t subsystem_u16;
  uint16_t dllCharacteristics_u16;
  uint64_t sizeOfStackReserve_u64;
  uint64_t sizeOfStackCommit_u64;
  uint64_t sizeOfHeapReserve_u64;
  uint64_t sizeOfHeapCommit_u64;
  uint32_t loaderFlags_u32;
  uint32_t numberOfRvaAndSizes_u32;

  DataDirectory* dataDir;
  PESection* sections;

  // mapping flag types and strings
  std::map<uint32_t, std::string> mapSectionFlags;
  std::map<uint16_t, std::string> mapPEFlagTypes;
  std::map<uint16_t, std::string> mapImageCharacteristics;
  std::map<uint16_t, std::string> mapMachineType;
  std::map<uint8_t, std::string> mapImageSubsystem;

  // section_table_t    *section_table;
  // data_directory_t   *dataDirectory;
  // export_directory_t  exportDir;
  // import_directory_t  *importDir;
  // to be implemented:
  //    resources directory
  //    base relocation table
  //    debug table
  //    tls table
  //    load config table
  //    delay import descriptor
  ///////////////
};

#endif
