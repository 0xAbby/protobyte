// elf.cpp
//    Definitions and declarations for PE module
//
//  https://github.com/0xAbby/binlyzer
//
// Author:
//  Abdullah Ada (0xabby)
//

#include "headers.h"
void ELF::parse32(std::ifstream& file, int endian) {

    // Elf header
    e_type_u16 = read16_le(file);
    e_machine_u16 = read16_le(file);
    e_version_u32 = read32_le(file);
    e_entry_u64 = read32_le(file);
    e_phoff_u64 = read32_le(file);
    e_shoff_u64 = read32_le(file);
    e_flags_u32 = read32_le(file);
    e_ehsize_u16 = read16_le(file);
    e_phentsize_u16 = read16_le(file);
    e_phnum_u16 = read16_le(file);
    e_shentsize_u16 = read16_le(file);
    e_shnum_u16 = read16_le(file);
    e_shstrndx_u16 = read16_le(file);

    // program header
    p_type_u32 = read32_le(file);
    p_offset_u64 = read32_le(file);
    p_vaddr_u64 = read32_le(file);
    p_paddr_u64 = read32_le(file);
    p_filesz_u64 = read32_le(file);
    p_memsz_u64 = read32_le(file);
    p_flags_u32 = read32_le(file);
    p_align_u64 = read32_le(file);

    // section header
    sh_name_u32 = read32_le(file); 
    sh_type_u32 = read32_le(file);
    sh_flags_u64 = read32_le(file);
    sh_addr_u64 = read32_le(file);
    sh_offset_u64 = read32_le(file);
    sh_size_u64 = read32_le(file);
    sh_link_u32 = read32_le(file);
    sh_info_u32 = read32_le(file);
    sh_addralign_u64 = read32_le(file);
    sh_entsize_u64 = read32_le(file);
}
void ELF::parse64(std::ifstream& file, int endian) {

    // Elf header
    e_type_u16 = read16_le(file);
    e_machine_u16 = read16_le(file);
    e_version_u32 = read32_le(file);
    e_entry_u64 = read64_le(file);
    e_phoff_u64 = read64_le(file);
    e_shoff_u64 = read64_le(file);
    e_flags_u32 = read32_le(file);
    e_ehsize_u16 = read16_le(file);
    e_phentsize_u16 = read16_le(file);
    e_phnum_u16 = read16_le(file);
    e_shentsize_u16 = read16_le(file);
    e_shnum_u16 = read16_le(file);
    e_shstrndx_u16 = read16_le(file);

    // program header
    p_type_u32 = read32_le(file);
    p_flags_u32 = read32_le(file);
    p_offset_u64 = read64_le(file);
    p_vaddr_u64 = read64_le(file);
    p_paddr_u64 = read64_le(file);
    p_filesz_u64 = read64_le(file);
    p_memsz_u64 = read64_le(file);
    p_align_u64 = read64_le(file);

    // section header
    sh_name_u32 = read32_le(file); 
    sh_type_u32 = read32_le(file);
    sh_flags_u64 = read64_le(file);
    sh_addr_u64 = read64_le(file);
    sh_offset_u64 = read64_le(file);
    sh_size_u64 = read64_le(file);
    sh_link_u32 = read32_le(file);
    sh_info_u32 = read32_le(file);
    sh_addralign_u64 = read64_le(file);
    sh_entsize_u64 = read64_le(file);
}

