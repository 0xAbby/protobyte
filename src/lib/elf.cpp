/**
 * @file elf.cpp
 * @brief  Implementations for functions that deal with ELF file format.
 *
 * @ref https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */

#include "../headers.h"

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
  
  programHeaderType_m.insert(pair<uint32_t, string>(0, "PT_NULL"));
  programHeaderType_m.insert(pair<uint32_t, string>(1, "PT_LOAD"));
  programHeaderType_m.insert(pair<uint32_t, string>(2, "PT_DYNAMIC"));
  programHeaderType_m.insert(pair<uint32_t, string>(3, "PT_INTERP"));
  programHeaderType_m.insert(pair<uint32_t, string>(4, "PT_NOTE"));
  programHeaderType_m.insert(pair<uint32_t, string>(5, "PT_SHLIB"));
  programHeaderType_m.insert(pair<uint32_t, string>(6, "PT_PHDR"));
  programHeaderType_m.insert(pair<uint32_t, string>(7, "PT_TLS"));
  programHeaderType_m.insert(pair<uint32_t, string>(8, "PT_NUM"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x60000000, "PT_LOOS"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x6474e550, "PT_GNU_EH_FRAME"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x6474e551, "PT_GNU_STACK"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x6474e552, "PT_GNU_RELRO"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x6474e553, "PT_GNU_PROPERTY"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x6ffffffa, "PT_LOSUNW"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x6ffffffa, "PT_SUNWBSS"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x6ffffffb, "PT_SUNWSTACK"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x6fffffff, "PT_HISUNW"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x6fffffff, "PT_HIOS"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x70000000, "PT_LOPROC"));
  programHeaderType_m.insert(pair<uint32_t, string>(0x7fffffff, "PT_HIPROC"));
  
  programHeaderFlag_m.insert(pair<uint32_t, std::string>(0, "None"));
  programHeaderFlag_m.insert(pair<uint32_t, std::string>(1, "Execute (PF_X)"));
  programHeaderFlag_m.insert(pair<uint32_t, std::string>(2, "Write (PF_W)"));
  programHeaderFlag_m.insert(pair<uint32_t, std::string>(3, "Write/Execute (PF_WX)"));
  programHeaderFlag_m.insert(pair<uint32_t, std::string>(4, "Read (PF_R)"));
  programHeaderFlag_m.insert(pair<uint32_t, std::string>(5, "Read/Execute (PF_RX)"));
  programHeaderFlag_m.insert(pair<uint32_t, std::string>(6, "Read/Write (PF_RW)"));
  programHeaderFlag_m.insert(pair<uint32_t, std::string>(7, "Read/Write/Execute (PF_RWX)"));
  programHeaderFlag_m.insert(pair<uint32_t, std::string>(0x0ff00000, "PF_MASKOS"));
  programHeaderFlag_m.insert(pair<uint32_t, std::string>(0xf0000000, "PF_MASKPROC"));

  sectionHeaderType_m.insert(pair<uint32_t, string>(0, "SHT_NULL"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(1, "SHT_PROGBITS"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(2, "SHT_SYMTAB"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(3, "SHT_STRTAB"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(4, "SHT_RELA"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(5, "SHT_HASH"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(6, "SHT_DYNAMIC"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(7, "SHT_NOTE"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(8, "SHT_NOBITS"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(9, "SHT_REL"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(10, "SHT_SHLIB"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(11, "SHT_DYNSYM"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(14, "SHT_INIT_ARRAY"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(15, "SHT_FINI_ARRAY"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(16, "SHT_PREINIT_ARRAY"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(17, "SHT_GROUP"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(18, "SHT_SYMTAB_SHNDX"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(19, "SHT_NUM"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x60000000, "SHT_LOOS"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6ffffff5, "SHT_GNU_ATTRIBUTES"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6ffffff6, "SHT_GNU_HASH"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6ffffff7, "SHT_GNU_LIBLIST"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6ffffff8, "SHT_CHECKSUM"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6ffffffa, "SHT_LOSUNW"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6ffffffa, "SHT_SUNW_move"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6ffffffb, "SHT_SUNW_COMDAT"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6ffffffc, "SHT_SUNW_syminfo"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6ffffffd, "SHT_GNU_verdef"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6ffffffe, "SHT_GNU_verneed"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6fffffff, "SHT_GNU_versym"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6fffffff, "SHT_HISUNW"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x6fffffff, "SHT_HIOS"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x70000000, "SHT_LOPROC"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x7fffffff, "SHT_HIPROC"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x80000000, "SHT_LOUSER"));
  sectionHeaderType_m.insert(pair<uint32_t, string>(0x8fffffff, "SHT_HIUSER"));  

  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0, "UNDEF"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xff00, "LORESERVE"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xff00, "LOPROC"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xff00, "BEFORE"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xff01, "AFTER"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xff1f, "HIPROC"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xff20, "LOOS"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xff3f, "HIOS"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xfff1, "ABS"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xfff2, "COMMON"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xffff, "XINDEX"));
  sectionHeaderFlag_m.insert(pair<uint32_t, string>(0xffff, "HIRESERVE"));
  
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

  // reading size of entries in program header and their numbers
  e_phentsize_u16 = FileIO::read_u16(file, littleEndian);
  e_phnum_u16 = FileIO::read_u16(file, littleEndian);

  // reading size of entries in section header and their numbers
  e_shentsize_u16 = FileIO::read_u16(file, littleEndian);
  e_shnum_u16 = FileIO::read_u16(file, littleEndian);

  e_shstrndx_u16 = FileIO::read_u16(file, littleEndian);

  // file seek to program header
  file.seekg(e_phoff_u64);
  /* read 'e_phnum_u16' of entries sized 'e_phentsize_u16'
  * program headers size:
  *            in 32bit: 32 byte long (n) arrays
  *            in 64bit: 56 byte long (n) arrays
  * ref https://wiki.osdev.org/ELF#Header
  */

  for(uint32_t idx = 0; idx < e_phnum_u16; idx++) {
    u_int64_t cur_offset = file.tellg();
    ProgramHeader pHeader;
    pHeader.setP_type(FileIO::read_u32(file, littleEndian));
    pHeader.setP_offset(FileIO::read_u32(file, littleEndian));
    pHeader.setP_vaddr(FileIO::read_u32(file, littleEndian));
    pHeader.setP_paddr(FileIO::read_u32(file, littleEndian));
    pHeader.setP_filesz(FileIO::read_u32(file, littleEndian));
    pHeader.setP_memsz(FileIO::read_u32(file, littleEndian));
    pHeader.setP_flags(FileIO::read_u32(file, littleEndian));
    pHeader.setP_align(FileIO::read_u32(file, littleEndian));

    programHeader.push_back(pHeader);
    // skip from where we started reading plus size of entry, to avoid wrong offsets
    file.seekg(cur_offset + e_phentsize_u16);
  }
  
  // file seek to section header
  file.seekg(e_shoff_u64);
  // read 'e_shentsize_u16' of entries sized 'e_shnum_u16'
  for(uint32_t idx = 0; idx < e_shentsize_u16; idx++) {
    u_int64_t cur_offset = file.tellg();
    SectionHeader sHeader;

    sHeader.setSh_name(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_type(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_flags(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_addr(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_offset(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_size(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_link(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_info(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_addralign(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_entsize(FileIO::read_u32(file, littleEndian));
    sectionHeader.push_back(sHeader);
    // skip from where we started reading plus size of entry, to avoid wrong offsets
    file.seekg(cur_offset + e_shentsize_u16);
  }

  // fill sections names
  file.clear();
  for(uint32_t idx = 0; idx < e_shnum_u16; idx++) {   
    uint32_t name_index = sectionHeader[idx].getSh_name();
    uint32_t table_offset = sectionHeader[e_shstrndx_u16].getSh_offset();
    std::string name = getSectionHeaderName(name_index, table_offset, file);
    sectionHeader[idx].setSh_name(name);
  }
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

  // reading size of entries in program header and their numbers
  e_phentsize_u16 = FileIO::read_u16(file, littleEndian);
  e_phnum_u16 = FileIO::read_u16(file, littleEndian);

  // reading size of entries in section header and their numbers
  e_shentsize_u16 = FileIO::read_u16(file, littleEndian);
  e_shnum_u16 = FileIO::read_u16(file, littleEndian);

  e_shstrndx_u16 = FileIO::read_u16(file, littleEndian);

  // file seek to program header
  file.seekg(e_phoff_u64);
  /* read 'e_phnum_u16' of entries sized 'e_phentsize_u16'
  * program headers size:
  *            in 32bit: 32 byte long (n) arrays
  *            in 64bit: 56 byte long (n) arrays
  * ref https://wiki.osdev.org/ELF#Header
  */

  for(uint32_t idx = 0; idx < e_phnum_u16; idx++) {
    u_int64_t cur_offset = file.tellg();
    ProgramHeader pHeader;
    pHeader.setP_type(FileIO::read_u32(file, littleEndian));
    pHeader.setP_flags(FileIO::read_u32(file, littleEndian));
    pHeader.setP_offset(FileIO::read_u64(file, littleEndian));
    pHeader.setP_vaddr(FileIO::read_u64(file, littleEndian));
    pHeader.setP_paddr(FileIO::read_u64(file, littleEndian));
    pHeader.setP_filesz(FileIO::read_u64(file, littleEndian));
    pHeader.setP_memsz(FileIO::read_u64(file, littleEndian));
    pHeader.setP_align(FileIO::read_u64(file, littleEndian));

    programHeader.push_back(pHeader);
    // skip from where we started reading plus size of entry, to avoid wrong offsets
    file.seekg(cur_offset + e_phentsize_u16);
  }
  
  // file seek to section header
  file.seekg(e_shoff_u64);
  // read 'e_shentsize_u16' of entries sized 'e_shnum_u16'
  for(uint32_t idx = 0; idx < e_shentsize_u16; idx++) {
    u_int64_t cur_offset = file.tellg();
    SectionHeader sHeader;

    sHeader.setSh_name(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_type(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_flags(FileIO::read_u64(file, littleEndian));
    sHeader.setSh_addr(FileIO::read_u64(file, littleEndian));
    sHeader.setSh_offset(FileIO::read_u64(file, littleEndian));
    sHeader.setSh_size(FileIO::read_u64(file, littleEndian));
    sHeader.setSh_link(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_info(FileIO::read_u32(file, littleEndian));
    sHeader.setSh_addralign(FileIO::read_u64(file, littleEndian));
    sHeader.setSh_entsize(FileIO::read_u64(file, littleEndian));
    
    sectionHeader.push_back(sHeader);
    // skip from where we started reading plus size of entry, to avoid wrong offsets
    file.seekg(cur_offset + e_shentsize_u16);
  }

  // fill sections names
  file.clear();
  for(uint32_t idx = 0; idx < e_shnum_u16; idx++) {   
    uint32_t name_index = sectionHeader[idx].getSh_name();
    uint32_t table_offset = sectionHeader[e_shstrndx_u16].getSh_offset();
    std::string name = getSectionHeaderName(name_index, table_offset, file);
    sectionHeader[idx].setSh_name(name);
  }
  
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
 * @param none
 * @return ELF's ei_class byte value.
 */
uint16_t ELF::getEi_class() const {
  return this->ei_class_u8;
}

/**
 * @brief Returns ELF's ei_data byte.
 * @param none
*/
uint16_t ELF::getEi_data() const {
  return this->ei_data_u8;
}

/**
 * @brief Returns ELF's ei_osabi byte.
 * @param none
  */
uint16_t ELF::getEi_osabi() const {
  return this->ei_osabi_u8;
}

/**
 * @brief Returns ELF's e_class flag bytes.
 * @param none
 */
std::map<uint16_t, std::string> ELF::getEclassFlags() const {
  return this->eclassFlags; 
}

/**
 * @brief Returns ELF's e_data flag bytes.
 * @param none
 */
std::map<uint16_t, std::string> ELF::getEdataFlags() const {
  return this->edataFlags;
}

/**
 * @brief Returns ELF's magic bytes.
 * @param none
 */
std::map<uint16_t, std::string> ELF::getEiosabiFlags() const {
  return this->eiosabiFlags; 
}

/**
 * @brief Returns ELF's e_type flag bytes.
 * @param none
 */
std::map<uint16_t, std::string> ELF::getEtypeFlags() const {
  return this->etypeFlags;
}

/**
 * @brief Returns ELF's e_machine flag bytes.
 * @param none
 */
std::map<uint16_t, std::string> ELF::getEmachineFlags() const {
  return this->emachineFlags;
}

/**
 * @brief Prints ELF's flag representation as a string to output.
 *
 * @param flag The ELF flag type to resolve (e.i. E_class, e_data...etc).
 * @param type The flag value, can be zero sometimes, or the value to be retrived
 * from the mapped strings in function mapFlags().
 * 
 * @return none.
 */
void ELF::printFlag(uint32_t flag, uint32_t type) {
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
  else if (flag == SECTIONTYPE)
      std::cout << this->sectionHeaderType_m[type] << std::endl;
  else if (flag == SECTIONFLAG)
      std::cout << this->sectionHeaderFlag_m[type] << std::endl;
  else if (flag == PROGRAMFLAG)
      std::cout << this->programHeaderFlag_m[type] << std::endl;
  else if (flag == PROGRAMTYPE)
      std::cout << this->programHeaderType_m[type] << std::endl;
}

/**
 * @brief Prints an ELF file's parsed information.
 * @param none
 * @return none
 */
void ELF::printElf() {
  using namespace std;
  cout << "Magic bytes: \t0x" << uppercase << hex << this->getMagicBytes() << " | ";
  this->printFlag(ECLASS, 0); 
  cout << "byte order: \t";
  this->printFlag(EDATA, 0);
  cout << "OS ABI: \t"; 
  this->printFlag(EIOSABI, 0);
  cout << "Type: \t";
  this->printFlag(ETYPE, 0);
  cout << "Machine: \t";
  this->printFlag(EMACHINE, 0);
  cout << "Entry Point: \t0x" << hex << this->getE_entry() << endl;
  cout << "Program headers offset : \t0x" << hex << this->getE_phoff() << endl;
  cout << "Program header entry size: \t0x" << this->getE_phentsize() << endl;
  cout << "total entries: \t0x" << this->getE_phnum() <<  endl;
  cout << "Section header offset: \t0x" << hex << this->getE_shoff() << endl;
  cout << "Section header entry size: \t0x" << this->getE_shentsize() << endl;
  cout << "total entries: \t0x" << this->getE_shnum() << endl << endl;

  cout << "---------------------------------\n";
  cout << "Program section entries\n";
  for (int idx = 0; idx < e_phnum_u16; idx++) {
    cout << "programHeader[" << dec << idx << "]\n";
    cout << "  Type: \t";
    this->printFlag(PROGRAMTYPE, programHeader[idx].getP_type());
    cout << "  Flags: \t";
    this->printFlag(PROGRAMFLAG, programHeader[idx].getP_flags()) ;
    cout << "  Offset: \t0x" << programHeader[idx].getP_offset() << endl;
    cout << "  Virtual Address: \t0x" << programHeader[idx].getP_vaddr() << endl;
    cout << "  Physical Address: \t0x" << programHeader[idx].getP_paddr() << endl;
    cout << "  Segment file length: \t0x" <<  programHeader[idx].getP_filesz() << endl;
    cout << "  Segment memory length: \t0x" <<  programHeader[idx].getP_memsz() << endl;
    cout << "  Alignment: \t0x" <<  programHeader[idx].getP_align() << endl << endl;
  }

  cout << "\n---------------------------------\n";
  cout << "Section section entries\n";
  for (int idx = 0; idx < e_shnum_u16; idx++) {
    cout << "sectionHeader[" << dec << idx << "]\n";
    cout << "  Name: \t" << sectionHeader[idx].getS_name() << endl;
    cout << "  Type: \t";
    this->printFlag(SECTIONTYPE, sectionHeader[idx].getSh_type());
    cout << "  flags: \t";
    this->printFlag(SECTIONTYPE, sectionHeader[idx].getSh_flags());
    cout << "  Address: \t0x" << sectionHeader[idx].getSh_addr() << endl;
    cout << "  Offset: \t0x" << sectionHeader[idx].getSh_offset() << endl;
    cout << "  size: \t0x" << sectionHeader[idx].getSh_size() << endl;
    cout << "  link: \t0x" << sectionHeader[idx].getSh_link() << endl;
    cout << "  info: \t0x" << sectionHeader[idx].getSh_info() << endl;
    cout << "  Address alignment: \t0x" << sectionHeader[idx].getSh_addralign() << endl;
    cout << "  Section size: \t0x" << sectionHeader[idx].getSh_entsize() << endl << endl;
  }
}

/**
 * @brief Returns an ELF's section header offset value.
 * @param none
 * @return 64 bits unsigned int.
 */
uint64_t ELF::getE_shoff() {
  return this->e_shoff_u64;
}

/**
 * @brief Returns an ELF's program header size value.
 * @param none
 * @return 16 bits unsigned int.
 */
uint16_t ELF::getE_phentsize() {
  return this->e_phentsize_u16;
}

/**
 * @brief Returns an ELF's number of program headers value.
 * @param none
 * @return 16 bits unsigned int.
 */
uint16_t ELF::getE_phnum() {
  return this->e_phnum_u16;
}

/**
 * @brief Returns an ELF's section header size value.
 * @param none
 * @return 16 bits unsigned int.
 */
uint16_t ELF::getE_shentsize() {
  return this->e_shentsize_u16;
}

/**
 * @brief Returns an ELF's number of section headers value.
 * @param none
 * @return 16 bits unsigned int.
 */
uint16_t ELF::getE_shnum() {
  return this->e_shnum_u16;
}

/**
 * @brief Returns the name of a section header.
 * 
 * @param nameOffset The offset in a file of where to read the name.
 * @param tableIndx The index of a section header that will contain an array of string names.
 * @param file A ifstream file object that is already opened for reading in binary.
 * 
 * @return a string object of type std::string.
 */
std::string ELF::getSectionHeaderName(uint32_t nameOffset, uint32_t tableIndx, std::ifstream& file) {
  // loop over vector of sections
  // if s_name and e_shntndex isn't zero
  // find the name of sectionHeader by offset
  // offset of name = sectionHeader[e_shstrndx_u16].sh_offset_u64[s_name];
  std::string name;

  if (nameOffset != 0) {
      file.clear();
      file.seekg(nameOffset + tableIndx, std::ios_base::beg);
      
      char ch;
      while(file.get(ch)){
          if (ch != '\0') {
            name += ch;
        } else {
            break;
        }
      }
      name += '\0';
  } else {
      return "None";
  }
      return name;
}

std::vector<SectionHeader> ELF::getSectionHeaders() const {
  return this->sectionHeader;
}

/************************ program headers ********************/

/**
 * @brief Sets the type of a program header section.
 * 
 * @param value The 4 bytes value to be set
 * 
 * @return None.
 */
void ProgramHeader::setP_type(uint32_t value) {
  this->p_type_u32 = value;
}

/**
 * @brief Sets the flags of a program header section.
 * 
 * @param value The 4 bytes value to be set
 * 
 * @return None.
 */
void ProgramHeader::setP_flags(uint32_t value) {
  this->p_flags_u32 = value;
}

/**
 * @brief Sets the offset of a program header section.
 * 
 * @param value The 64bit value to be set
 * 
 * @return None.
 */
void ProgramHeader::setP_offset(uint64_t value) {
  this->p_offset_u64 = value;
}

/**
 * @brief Sets the virtual address of a program header section.
 * 
 * @param value The 64bits value to be set
 * 
 * @return None.
 */
void ProgramHeader::setP_vaddr(uint64_t value) {
  this->p_vaddr_u64 = value;
}

/**
 * @brief Sets the physical address of a program header section.
 * 
 * @param value The 64bits value to be set
 * 
 * @return None.
 */
void ProgramHeader::setP_paddr(uint64_t value) {
  this->p_paddr_u64 = value;
}

/**
 * @brief Sets the filesz field of a program header section.
 * 
 * @param value The 64bits value to be set
 * 
 * @return None.
 */
void ProgramHeader::setP_filesz(uint64_t value) {
  this->p_filesz_u64 = value;
}

/**
 * @brief Sets the memsz field of a program header section.
 * 
 * @param value The 64bits value to be set
 * 
 * @return None.
 */
void ProgramHeader::setP_memsz(uint64_t value) {
    this->p_memsz_u64 = value;
}

/**
 * @brief Sets the alignment field of a program header section.
 * 
 * @param value The 64bits value to be set
 * 
 * @return None.
 */
void ProgramHeader::setP_align(uint64_t value) {
    this->p_align_u64 = value;
}

/**
 * @brief Gets the value of 'type' field in a program header section.
 * 
 * @param value The 4 bytes value to be set
 * 
 * @return None.
 */
uint32_t ProgramHeader::getP_type() {
  return this->p_type_u32;
}

/**
 * @brief Gets the value of 'flags' field in a program header section.
 * 
 * @return The 4 bytes value to be set
 */
uint32_t ProgramHeader::getP_flags() {
  return this->p_flags_u32;  
}

/**
 * @brief Gets the value of 'offset' field in a program header section.
 * 
 * @return The 8 bytes value to be set
 */
uint64_t ProgramHeader::getP_offset() {
  return this->p_offset_u64;
}

/**
 * @brief Gets the value of 'virtual address' field in a program header section.
 * 
 * @return The 8 bytes value to be set
 */
uint64_t ProgramHeader::getP_vaddr() {
  return this->p_vaddr_u64;  
}

/**
 * @brief Gets the value of 'physical address' field in a program header section.
 * 
 * @return The 8 bytes value to be set
 */
uint64_t ProgramHeader::getP_paddr() {
  return this->p_paddr_u64;  
}

/**
 * @brief Gets the value of 'filesz' field in a program header section.
 * 
 * @return The 8 bytes value to be set
 */
uint64_t ProgramHeader::getP_filesz() {
  return this->p_filesz_u64;  
}

/**
 * @brief Gets the value of 'memsz' field in a program header section.
 * 
 * @return The 8 bytes value to be set
 */
uint64_t ProgramHeader::getP_memsz() {
  return this->p_memsz_u64;  
}

/**
 * @brief Gets the value of 'alignment' field in a program header section.
 * 
 * @return The 8 bytes value to be set
 */
uint64_t ProgramHeader::getP_align() {
  return this->p_align_u64;
}
/********************** section header **************************/
void SectionHeader::setSh_name(uint32_t value) {
  this->sh_name_u32 = value;
}
void SectionHeader::setSh_type(uint32_t value) {
  this->sh_type_u32 = value;
}
void SectionHeader::setSh_flags(uint32_t value) {
  this->sh_flags_u64 = value;
}
void SectionHeader::setSh_addr(uint32_t value) {
  this->sh_addr_u64 = value;
}
void SectionHeader::setSh_offset(uint32_t value) {
  this->sh_offset_u64 = value;
}
void SectionHeader::setSh_size(uint32_t value) {
  this->sh_size_u64 = value;
}
void SectionHeader::setSh_link(uint32_t value) {
  this->sh_link_u32 = value;
}
void SectionHeader::setSh_info(uint32_t value) {
  this->sh_info_u32 = value;
}
void SectionHeader::setSh_addralign(uint32_t value) {
  this->sh_addralign_u64 = value;
}
void SectionHeader::setSh_entsize(uint32_t value) {
  this->sh_entsize_u64 = value;
}

uint32_t SectionHeader::getSh_name() {
  return this->sh_name_u32;
}
uint32_t SectionHeader::getSh_type() {
  return this->sh_type_u32;
}
uint32_t SectionHeader::getSh_flags() {
  return this->sh_flags_u64;
}
uint32_t SectionHeader::getSh_addr() {
  return this->sh_addr_u64;
}
uint32_t SectionHeader::getSh_offset() {
  return this->sh_offset_u64;
}
uint32_t SectionHeader::getSh_size() {
  return this->sh_size_u64;
}
uint32_t SectionHeader::getSh_link() {
  return this->sh_link_u32;
}
uint32_t SectionHeader::getSh_info() {
  return this->sh_info_u32;
}
uint32_t SectionHeader::getSh_addralign() {
  return this->sh_addralign_u64;
}
uint32_t SectionHeader::getSh_entsize() {
  return this->sh_entsize_u64;
}

/**
 * @brief Sets a section header's name.
 * 
 * @param name a string object containing the name.
 * 
 * @return None.
 */
void SectionHeader::setSh_name(std::string name) {
  this->name = name;
}

/**
 * @brief Gets the name of a section header.
 * 
 * @return A string object containing the name of section header
 */
std::string SectionHeader::getS_name() {
  return this->name;
}