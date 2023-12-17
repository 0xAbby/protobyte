// elf.h
//    Definitions and declarations for PE module
//
//  https://github.com/0xAbby/binlyzer
//
// Author:
//  Abdullah Ada (0xabby)
//
#ifndef ELF_H
#define ELF_H

#include "headers.h"

uint8_t read8_le(std::ifstream& in);
uint16_t read16_le(std::ifstream& in);
uint32_t read32_le(std::ifstream& in);
uint64_t read64_le(std::ifstream& in);

class ELF: public PE {
 private:
  // Elf64_Ehdr
  unsigned char e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;

  // Elf64_Phdr
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;

  // Elf64_Shdr
  uint32_t sh_name;
  uint32_t sh_type;
  uint64_t sh_flags;
  uint64_t sh_addr;
  uint64_t sh_offset;
  uint64_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint64_t sh_addralign;
  uint64_t sh_entsize;

 public:
  void parse64(std::ifstream& file);
  void parse32(std::ifstream& file);
  
  ELF() {}
  ELF(std::string filename) {
    std::ifstream file(filename, std::ios::binary);
    file.read(reinterpret_cast<char*> (e_ident), 16);

    if (1) {
        parse32(file);
    } else {
        parse64(file);
    }

    
  }
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