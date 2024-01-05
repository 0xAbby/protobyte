/**
 * @file elf.h
 * @brief  Definitions and declarations for ELF module
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#ifndef ELF_H
#define ELF_H

#include "headers.h"

class ELF {
 public:
  ELF();
  ELF(std::string filename);
  ~ELF();

  void parse64(std::ifstream& file, bool littleEndian);
  void parse32(std::ifstream& file, bool littleEndian);
  void readE_ident(std::ifstream& file);
  void init(std::string filename);
  void mapFlags();

  unsigned char* getE_ident();
  uint16_t getE_type();
  uint16_t getE_machine();
  uint64_t getE_phoff();
  uint64_t getE_entry();

 private:
  // Elf64_Ehdr
  unsigned char e_ident[16];
  uint16_t e_type_u16;
  uint16_t e_machine_u16;
  uint32_t e_version_u32;
  uint64_t e_entry_u64;
  uint64_t e_phoff_u64;
  uint64_t e_shoff_u64;
  uint32_t e_flags_u32;
  uint16_t e_ehsize_u16;
  uint16_t e_phentsize_u16;
  uint16_t e_phnum_u16;
  uint16_t e_shentsize_u16;
  uint16_t e_shnum_u16;
  uint16_t e_shstrndx_u16;

  // Elf64_Phdr
  uint32_t p_type_u32;
  uint32_t p_flags_u32;
  uint64_t p_offset_u64;
  uint64_t p_vaddr_u64;
  uint64_t p_paddr_u64;
  uint64_t p_filesz_u64;
  uint64_t p_memsz_u64;
  uint64_t p_align_u64;

  // Elf64_Shdr
  uint32_t sh_name_u32;
  uint32_t sh_type_u32;
  uint64_t sh_flags_u64;
  uint64_t sh_addr_u64;
  uint64_t sh_offset_u64;
  uint64_t sh_size_u64;
  uint32_t sh_link_u32;
  uint32_t sh_info_u32;
  uint64_t sh_addralign_u64;
  uint64_t sh_entsize_u64;


  std::map<uint32_t, std::string> etypeFlags;
  std::map<uint32_t, std::string> emachineFlags;
  std::map<uint32_t, std::string> eclassFlags;
  std::map<uint32_t, std::string> edataFlags;
  std::map<uint32_t, std::string> eiosabiFlags;
};

/*
Important sections:
.interp
.init
.plt
.text
.fini
.rodata
.data
.bss
.shstrtab
*/

#endif