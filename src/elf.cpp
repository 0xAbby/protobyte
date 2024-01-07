/**
 * @file elf.cpp
 * @brief  Implementations for functions that deal with ELF file format.
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */

#include "headers.h"

ELF::ELF() {}
ELF::~ELF() {}

/**
 * @brief ELF class constructor to pass filename to init() for parsing.
 *
 * @return none.
 */
ELF::ELF(std::string filename) {
//  init(filename);
}

/**
 * @brief Initiates parsing by calling releavant methods.
 * 
 * @param filename a string object containing name of file to parse.
 *
 * @return none.
 */
void ELF::init(std::string filename) {
  std::ifstream file(filename, std::ios::binary);

  magicBytes_u32 = FileIO::read_u32(file, false);
  ei_class_u8 =  FileIO::read_u8(file);
  ei_data_u8  = FileIO::read_u8(file);
  ei_version_u8 = FileIO::read_u8(file);
  ei_osabi_u8 = FileIO::read_u8(file);

  // skipping e_ident field.
  file.seekg(0x10);
  
  if (ei_class_u8 & 1) {
    parse32(file, ei_data_u8);
  } else if (ei_class_u8 & 2) {
    parse64(file, ei_data_u8);
  }

  mapFlags();
}

/**
 * @brief Saves integer IDs and their meanings into mappings.
 *
 * @return none.
 */
void ELF::mapFlags() {
  using namespace std;
  etypeFlags.insert(pair<uint16_t, string>(0, "NONE"));
  etypeFlags.insert(pair<uint16_t, string>(1, "ET_REL"));
  etypeFlags.insert(pair<uint16_t, string>(2, "ET_EXEC"));
  etypeFlags.insert(pair<uint16_t, string>(3, "Dynamic / Position Independant ET_DYN"));
  etypeFlags.insert(pair<uint16_t, string>(4, "ET_CORE"));
  etypeFlags.insert(pair<uint16_t, string>(5, "ET_LOOS"));

  emachineFlags.insert(pair<uint16_t, string>(40, "ARM (EM_ARM)"));
  emachineFlags.insert(pair<uint16_t, string>(41, "EM_ALPHA"));
  emachineFlags.insert(pair<uint16_t, string>(50, "EM_IA_64"));
  emachineFlags.insert(pair<uint16_t, string>(51, "EM_MIPS_X"));
  emachineFlags.insert(pair<uint16_t, string>(62, "64bit (EM_X86_64)"));
  emachineFlags.insert(pair<uint16_t, string>(3, "Intel 386 (EM_386)"));
  emachineFlags.insert(pair<uint16_t, string>(8, "MIPS (EM_MIPS)"));
  emachineFlags.insert(pair<uint16_t, string>(10, "EM_MIPS_RS3_LE"));

  eclassFlags.insert(pair<uint16_t, string>(1, "32bit (ELFCLASS32)"));
  eclassFlags.insert(pair<uint16_t, string>(2, "64bit (ELFCLASS64)"));

  edataFlags.insert(pair<uint16_t, string>(1, "Least Significant Byte (LSB)"));
  edataFlags.insert(pair<uint16_t, string>(2, "Most Significant Byte (MSB)"));

  eiosabiFlags.insert(pair<uint16_t, string>(0, "NONE"));
  eiosabiFlags.insert(pair<uint16_t, string>(1, "HPUX"));
  eiosabiFlags.insert(pair<uint16_t, string>(2, "NETBSD"));
  eiosabiFlags.insert(pair<uint16_t, string>(3, "Linux"));
  eiosabiFlags.insert(pair<uint16_t, string>(6, "SOLARIS"));
  eiosabiFlags.insert(pair<uint16_t, string>(7, "AIX"));
  eiosabiFlags.insert(pair<uint16_t, string>(8, "IRIX"));
  eiosabiFlags.insert(pair<uint16_t, string>(9, "FREEBSD"));
  eiosabiFlags.insert(pair<uint16_t, string>(10, "TRU64"));
  eiosabiFlags.insert(pair<uint16_t, string>(12, "OPENBSD"));
  eiosabiFlags.insert(pair<uint16_t, string>(64, "ARM_AEABI"));
  eiosabiFlags.insert(pair<uint16_t, string>(97, "ARM"));
}

/**
 * @brief Given an ifstream file object, it parses ELF header, segments, and
 * sections. then prints out basic info parsed.
 *
 * @param file An std::ifstream object with ELF file already opened,
 * assumption here is that the stream object is at offset after e_ident.
 * @param littleEndian Indicates True little end byte order.
 *
 * @return none.
 */
void ELF::parse32(std::ifstream& file, bool littleEndian) {
  file.seekg(0x10);
  // Elf header
  e_type_u16 = FileIO::read_u16(file, littleEndian);
  e_machine_u16 = FileIO::read_u16(file, littleEndian);
  e_version_u32 = FileIO::read_u32(file, littleEndian);
  e_entry_u64 = FileIO::read_u32(file, littleEndian);
  e_phoff_u64 = FileIO::read_u32(file, littleEndian);
  e_shoff_u64 = FileIO::read_u32(file, littleEndian);
  e_flags_u32 = FileIO::read_u32(file, littleEndian);
  e_ehsize_u16 = FileIO::read_u16(file, littleEndian);
  e_phentsize_u16 = FileIO::read_u16(file, littleEndian);
  e_phnum_u16 = FileIO::read_u16(file, littleEndian);
  e_shentsize_u16 = FileIO::read_u16(file, littleEndian);
  e_shnum_u16 = FileIO::read_u16(file, littleEndian);
  e_shstrndx_u16 = FileIO::read_u16(file, littleEndian);

  // skip to section header table;
  file.seekg(e_shoff_u64);

  uint32_t sh_name_u32 = FileIO::read_u32(file, littleEndian);
  uint32_t sh_type_u32 = FileIO::read_u32(file, littleEndian);
  uint64_t sh_flags_u64 = FileIO::read_u32(file, littleEndian);
  uint64_t sh_addr_u64 = FileIO::read_u32(file, littleEndian);
  uint64_t sh_offset_u64 = FileIO::read_u32(file, littleEndian);
  uint64_t sh_size_u64 = FileIO::read_u32(file, littleEndian);
  uint32_t sh_link_u32 = FileIO::read_u32(file, littleEndian);
  uint32_t sh_info_u32 = FileIO::read_u32(file, littleEndian);
  uint64_t sh_addralign_u64 = FileIO::read_u32(file, littleEndian);
  uint64_t sh_entsize_u64 = FileIO::read_u32(file, littleEndian);
}

/**
 * @brief Given an ifstream file object, it parses ELF header, segments, and
 * sections. then prints out basic info parsed.
 *
 * @param file An std::ifstream object with ELF file already opened,
 * assumption here is that the stream object is at offset after e_ident.
 * @param littleEndian Indicate byte order. True: little end, False: Big end.
 *
 * @return none.
 */
void ELF::parse64(std::ifstream& file, bool littleEndian) {
  file.seekg(0x10);
  // Elf header
  e_type_u16 = FileIO::read_u16(file, littleEndian);
  e_machine_u16 = FileIO::read_u16(file, littleEndian);
  e_version_u32 = FileIO::read_u32(file, littleEndian);
  e_entry_u64 = FileIO::read_u64(file, littleEndian);
  e_phoff_u64 = FileIO::read_u64(file, littleEndian);
  e_shoff_u64 = FileIO::read_u64(file, littleEndian);
  e_flags_u32 = FileIO::read_u32(file, littleEndian);
  e_ehsize_u16 = FileIO::read_u16(file, littleEndian);
  e_phentsize_u16 = FileIO::read_u16(file, littleEndian);
  e_phnum_u16 = FileIO::read_u16(file, littleEndian);
  e_shentsize_u16 = FileIO::read_u16(file, littleEndian);
  e_shnum_u16 = FileIO::read_u16(file, littleEndian);
  e_shstrndx_u16 = FileIO::read_u16(file, littleEndian);
}

/**
 * @brief Given an ifstream file object, read the first 16 bytes.
 *
 * @param file An std::ifstream object with ELF file already opened,
 * assumption here is that the stream object is at offset 0.
 *
 * @return none.
 */
void ELF::readE_ident(std::ifstream& file) {
  unsigned char bytes[2];

  for (int idx = 0; idx < 16; idx++) {
    file.get(reinterpret_cast<char*>(bytes), 1);
    e_ident[idx] = bytes[0];
    return;
  }
}


/**
 * @brief Returns ELF's E_ident.
 *
 */
unsigned char* ELF::getE_ident() {
  return this->e_ident;
}
/**
 * @brief Returns ELF's E_type.
 *
 */
uint16_t ELF::getE_type() const {
  return this->e_type_u16;
}

/**
 * @brief Returns ELF's E_machine.
 *
 * @return ELF's e_machine value.
 */
uint16_t ELF::getE_machine() const {
  return this->e_machine_u16;
}

/**
 * @brief Returns ELF's E_phoff.
 *
 */
uint64_t ELF::getE_phoff() const {
  return this->e_phoff_u64;
}

/**
 * @brief Returns ELF's E_entry.
 *
 */
uint64_t ELF::getE_entry() const {
  return this->e_entry_u64;
}

/**
 * @brief Returns ELF's magic bytes.
 *
 */
uint32_t ELF::getMagicBytes() const {
  return this->magicBytes_u32;
}

/**
 * @brief Returns ELF's ei_class byte.
 *
 * @return ELF's ei_class byte value.
 */
uint16_t ELF::getEi_class() const {
  return this->ei_class_u8;
}

/**
 * @brief Returns ELF's ei_data byte.
 *
  */
uint16_t ELF::getEi_data() const {
  return this->ei_data_u8;
}

/**
 * @brief Returns ELF's ei_osabi byte.
 *
  */
uint16_t ELF::getEi_osabi() const {
  return this->ei_osabi_u8;
}

/**
 * @brief Returns ELF's e_class flag bytes.
 *
 */
std::map<uint16_t, std::string> ELF::getEclassFlags() const {
  return this->eclassFlags; 
}

/**
 * @brief Returns ELF's e_data flag bytes.
 *
 */
std::map<uint16_t, std::string> ELF::getEdataFlags() const {
  return this->edataFlags;
}

/**
 * @brief Returns ELF's magic bytes.
 *
 */
std::map<uint16_t, std::string> ELF::getEiosabiFlags() const {
  return this->eiosabiFlags; 
}

/**
 * @brief Returns ELF's e_type flag bytes.
 *
 */
std::map<uint16_t, std::string> ELF::getEtypeFlags() const {
  return this->etypeFlags;
}

/**
 * @brief Returns ELF's e_machine flag bytes.
 *
 */
std::map<uint16_t, std::string> ELF::getEmachineFlags() const {
  return this->emachineFlags;
}

void ELF::printFlag(uint32_t flag) {
  if (flag == ECLASS)
      std::cout << this->eclassFlags[ei_class_u8] << std::endl;
  else if (flag == EDATA)
      std::cout << this->edataFlags[ei_data_u8] << std::endl;
  else if (flag == EMACHINE)
      std::cout << this->emachineFlags[e_machine_u16] << std::endl;
  else if (flag == EIOSABI)
      std::cout << this->eiosabiFlags[ei_osabi_u8] << std::endl;
  else if (flag == ETYPE)
      std::cout << this->etypeFlags[e_type_u16] << std::endl;
}

void ELF::printElf() {
  using namespace std;
  cout << "Magic bytes: \t0x" << hex << this->getMagicBytes() << " | ";
  this->printFlag(ECLASS); 
  cout << "byte order: \t";
  this->printFlag(EDATA);
  cout << "OS ABI: \t"; 
  this->printFlag(EIOSABI);
  cout << "Type: \t";
  this->printFlag(ETYPE);
  cout << "Machine: \t";
  this->printFlag(EMACHINE);
  cout << "Entry Point: \t0x" << hex << this->getE_entry() << endl;
}