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
ELF::ELF(std::string filename) {
  init(filename);
}

void ELF::init(std::string filename) {
  std::ifstream file(filename, std::ios::binary);
  file.get(reinterpret_cast<char*>(e_ident), 16);

  if (e_ident[4] & 1) {
    // e_ident's 6th byte indicates 1: LSB / 2: MSB
    parse32(file, e_ident[5] & 1);
    // std::cout << " 32 bit" << std::endl;
  } else if (e_ident[4] & 2) {
    parse64(file, e_ident[5] & 1);
    // std::cout << "64 bit" << std::endl;
  }

  mapFlags();
  // print basic info
  using namespace std;
  cout << "Magic bytes: \t" << hex << e_ident << endl;
  cout << "Architecture: \t" << eclassFlags[e_ident[4]] << endl;
  cout << "Byte order: \t" << edataFlags[e_ident[5]] << endl;
  cout << "Flags: \t\t" << emachineFlags[e_machine_u16] << " " << etypeFlags[e_type_u16] << endl;
  cout << "Entry point address: \t\t0x" << hex << e_entry_u64 << endl;
}


void ELF::mapFlags() {
  using namespace std;
  etypeFlags.insert(pair<uint32_t, string>(0, "NONE"));
  etypeFlags.insert(pair<uint32_t, string>(1, "ET_REL"));
  etypeFlags.insert(pair<uint32_t, string>(2, "ET_EXEC"));
  etypeFlags.insert(pair<uint32_t, string>(3, "ET_DYN"));
  etypeFlags.insert(pair<uint32_t, string>(4, "ET_CORE"));
  etypeFlags.insert(pair<uint32_t, string>(5, "ET_LOOS"));

  emachineFlags.insert(pair<uint32_t, string>(40, "ARM (EM_ARM)"));
  emachineFlags.insert(pair<uint32_t, string>(41, "EM_ALPHA"));
  emachineFlags.insert(pair<uint32_t, string>(50, "EM_IA_64"));
  emachineFlags.insert(pair<uint32_t, string>(51, "EM_MIPS_X"));
  emachineFlags.insert(pair<uint32_t, string>(62, "64bit (EM_X86_64)"));
  emachineFlags.insert(pair<uint32_t, string>(3, "intel 386 (EM_386)"));
  emachineFlags.insert(pair<uint32_t, string>(8, "MIPS (EM_MIPS)"));
  emachineFlags.insert(pair<uint32_t, string>(10, "EM_MIPS_RS3_LE"));

  eclassFlags.insert(pair<uint32_t, string>(1, "32bit (ELFCLASS32)"));
  eclassFlags.insert(pair<uint32_t, string>(2, "64bit (ELFCLASS64)"));

  edataFlags.insert(pair<uint32_t, string>(1, "Little Endian (LSB)"));
  edataFlags.insert(pair<uint32_t, string>(2, "Big Endian (MSB)"));

  eiosabiFlags.insert(pair<uint32_t, string>(0, "NONE"));
  eiosabiFlags.insert(pair<uint32_t, string>(1, "HPUX"));
  eiosabiFlags.insert(pair<uint32_t, string>(2, "NETBSD"));
  eiosabiFlags.insert(pair<uint32_t, string>(3, "Linux"));
  eiosabiFlags.insert(pair<uint32_t, string>(6, "SOLARIS"));
  eiosabiFlags.insert(pair<uint32_t, string>(7, "AIX"));
  eiosabiFlags.insert(pair<uint32_t, string>(8, "IRIX"));
  eiosabiFlags.insert(pair<uint32_t, string>(9, "FREEBSD"));
  eiosabiFlags.insert(pair<uint32_t, string>(10, "TRU64"));
  eiosabiFlags.insert(pair<uint32_t, string>(12, "OPENBSD"));
  eiosabiFlags.insert(pair<uint32_t, string>(64, "ARM_AEABI"));
  eiosabiFlags.insert(pair<uint32_t, string>(97, "ARM"));


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
  e_type_u16 = read_u16(file, littleEndian);
  e_machine_u16 = read_u16(file, littleEndian);
  e_version_u32 = read_u32(file, littleEndian);
  e_entry_u64 = read_u32(file, littleEndian);
  e_phoff_u64 = read_u32(file, littleEndian);
  e_shoff_u64 = read_u32(file, littleEndian);
  e_flags_u32 = read_u32(file, littleEndian);
  e_ehsize_u16 = read_u16(file, littleEndian);
  e_phentsize_u16 = read_u16(file, littleEndian);
  e_phnum_u16 = read_u16(file, littleEndian);
  e_shentsize_u16 = read_u16(file, littleEndian);
  e_shnum_u16 = read_u16(file, littleEndian);
  e_shstrndx_u16 = read_u16(file, littleEndian);
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
  e_type_u16 = read_u16(file, littleEndian);
  e_machine_u16 = read_u16(file, littleEndian);
  e_version_u32 = read_u32(file, littleEndian);
  e_entry_u64 = read_u64(file, littleEndian);
  e_phoff_u64 = read_u64(file, littleEndian);
  e_shoff_u64 = read_u64(file, littleEndian);
  e_flags_u32 = read_u32(file, littleEndian);
  e_ehsize_u16 = read_u16(file, littleEndian);
  e_phentsize_u16 = read_u16(file, littleEndian);
  e_phnum_u16 = read_u16(file, littleEndian);
  e_shentsize_u16 = read_u16(file, littleEndian);
  e_shnum_u16 = read_u16(file, littleEndian);
  e_shstrndx_u16 = read_u16(file, littleEndian);
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

uint16_t read16_be(std::ifstream& in) {
  uint16_t value = 0;
  unsigned char ch[3] = {0};

  in.read(reinterpret_cast<char*>(ch), 2);
  value = uint16_t(ch[0]) << 8;
  value |= uint16_t(ch[1]);

  return value;
}
/**
 * @brief Reads 32 bits and returns them in big endian byte order.
 *
 * @param in An std::ifstream object with PE file already opened,
 *
 * @return a 32 bit unsigned integer.
 */
uint32_t read32_be(std::ifstream& in) {
  uint32_t value = 0;
  unsigned char ch[4] = {0};

  in.read(reinterpret_cast<char*>(ch), 4);

  value |= uint32_t(ch[0]) << 24;
  value |= uint32_t(ch[1]) << 16;
  value |= uint32_t(ch[2]) << 8;
  value |= uint32_t(ch[3]);

  return value;
}
uint64_t read64_be(std::ifstream& in) {
  uint64_t value = 0;
  unsigned char ch[9] = {0};

  in.read(reinterpret_cast<char*>(ch), 8);
  value |= uint64_t(ch[0]) << 56;
  value |= uint64_t(ch[1]) << 48;
  value |= uint64_t(ch[2]) << 40;
  value |= uint64_t(ch[3]) << 32;
  value |= uint64_t(ch[4]) << 24;
  value |= uint64_t(ch[5]) << 16;
  value |= uint64_t(ch[6]) << 8;
  value |= uint64_t(ch[7]);

  return value;
}

unsigned char* ELF::getE_ident() {
  return this->e_ident;
}
uint16_t ELF::getE_type() {
  return this->e_type_u16;
}
uint16_t ELF::getE_machine() {
  return this->e_machine_u16;
}
uint64_t ELF::getE_phoff() {
  return this->e_phoff_u64;
}
uint64_t ELF::getE_entry() {
  return this->e_entry_u64;
}