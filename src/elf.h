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

#pragma once
#include "headers.h"

uint8_t read8_le(std::ifstream& in);
uint16_t read16_le(std::ifstream& in);
uint32_t read32_le(std::ifstream& in);
uint64_t read64_le(std::ifstream& in);

uint16_t read16_be(std::ifstream& in);
uint32_t read32_be(std::ifstream& in);
uint64_t read64_be(std::ifstream& in);

class ELF {
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

 public:
  void parse64(std::ifstream& file, bool littleEndian);
  void parse32(std::ifstream& file, bool littleEndian);
  void readE_ident(std::ifstream& file);
  
  ELF() {}
  ELF(std::string filename) { init(filename); }

  void init(std::string filename) {
    std::ifstream file(filename, std::ios::binary);
    file.get(reinterpret_cast<char*> (e_ident), 16);
    
    if (e_ident[4] & 1) {
        parse32(file, e_ident[5] & 1);
        std::cout << " 32 bit" << std::endl;
    } 
    else if (e_ident[4] & 2) {
        // e_ident's 6th byte indicates 1: LSB / 2: MSB
        parse64(file, e_ident[5] & 1);
        //std::cout << "64 bit" << std::endl;
    }    
  }

  auto getE_ident() { return this->e_ident; }
  auto getE_type() { return this->e_type_u16; }
  auto getE_machine() { return this->e_machine_u16; }
  auto getE_phoff() { return this->e_phoff_u64; }
  auto getE_entry() { return this->e_entry_u64; }
  

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