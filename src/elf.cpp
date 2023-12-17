// elf.cpp
//    Definitions and declarations for PE module
//
//  https://github.com/0xAbby/binlyzer
//
// Author:
//  Abdullah Ada (0xabby)
//

#include "headers.h"
void ELF::parse32(std::ifstream& file) {

    // Elf header
    e_type = read16_le(file);
    e_machine = read16_le(file);
    e_version = read32_le(file);
    e_entry = read32_le(file);
    e_phoff = read32_le(file);
    e_shoff = read32_le(file);
    e_flags = read32_le(file);
    e_ehsize = read16_le(file);
    e_phentsize = read16_le(file);
    e_phnum = read16_le(file);
    e_shentsize = read16_le(file);
    e_shnum = read16_le(file);
    e_shstrndx = read16_le(file);

    // program header
    p_type = read32_le(file);
    p_offset = read32_le(file);
    p_vaddr = read32_le(file);
    p_paddr = read32_le(file);
    p_filesz = read32_le(file);
    p_memsz = read32_le(file);
    p_flags = read32_le(file);
    p_align = read32_le(file);

    // section header
    sh_name = read32_le(file); 
    sh_type = read32_le(file);
    sh_flags = read32_le(file);
    sh_addr = read32_le(file);
    sh_offset = read32_le(file);
    sh_size = read32_le(file);
    sh_link = read32_le(file);
    sh_info = read32_le(file);
    sh_addralign = read32_le(file);
    sh_entsize = read32_le(file);
}
void ELF::parse64(std::ifstream& file) {

    // Elf header
    e_type = read16_le(file);
    e_machine = read16_le(file);
    e_version = read32_le(file);
    e_entry = read64_le(file);
    e_phoff = read64_le(file);
    e_shoff = read64_le(file);
    e_flags = read32_le(file);
    e_ehsize = read16_le(file);
    e_phentsize = read16_le(file);
    e_phnum = read16_le(file);
    e_shentsize = read16_le(file);
    e_shnum = read16_le(file);
    e_shstrndx = read16_le(file);

    // program header
    p_type = read32_le(file);
    p_flags = read32_le(file);
    p_offset = read64_le(file);
    p_vaddr = read64_le(file);
    p_paddr = read64_le(file);
    p_filesz = read64_le(file);
    p_memsz = read64_le(file);
    p_align = read64_le(file);

    // section header
    sh_name = read32_le(file); 
    sh_type = read32_le(file);
    sh_flags = read64_le(file);
    sh_addr = read64_le(file);
    sh_offset = read64_le(file);
    sh_size = read64_le(file);
    sh_link = read32_le(file);
    sh_info = read32_le(file);
    sh_addralign = read64_le(file);
    sh_entsize = read64_le(file);
}

