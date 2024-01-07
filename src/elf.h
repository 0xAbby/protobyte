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


class SectionHeader {
  public:
    void setSh_name_u32(uint32_t);
    void setSh_type_u32(uint32_t);
    void setSh_flags_u64(uint32_t);
    void setSh_addr_u64(uint32_t);
    void setSh_offset_u64(uint32_t);
    void setSh_size_u64(uint32_t);
    void setSh_link_u32(uint32_t);
    void setSh_info_u32(uint32_t);
    void setSh_addralign_u64(uint32_t);
    void setSh_entsize_u64(uint32_t);

    uint32_t getSh_name_u32(uint32_t);
    uint32_t getSh_type_u32(uint32_t);
    uint32_t getSh_flags_u64(uint32_t);
    uint32_t getSh_addr_u64(uint32_t);
    uint32_t getSh_offset_u64(uint32_t);
    uint32_t getSh_size_u64(uint32_t);
    uint32_t getSh_link_u32(uint32_t);
    uint32_t getSh_info_u32(uint32_t);
    uint32_t getSh_addralign_u64(uint32_t);
    uint32_t getSh_entsize_u64(uint32_t);

  private:
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
};

/**
 * @brief ELF class handles parsing specific ELF format.
 */
class ELF {
 public:
  // disabling move/copy constructors
  ELF(ELF&) = delete;
  ELF(ELF&& other) = delete;
  ELF & operator=( ELF&) = delete;

  ELF();
  ~ELF();
  ELF(std::string filename);
  
  virtual void init(std::string filename);
  
  void parse64(std::ifstream& file, bool littleEndian);
  void parse32(std::ifstream& file, bool littleEndian);
  void readE_ident(std::ifstream& file);
  void mapFlags();
  void printElf();

  unsigned char* getE_ident();
  uint16_t getE_type() const;
  uint16_t getE_machine() const;
  uint64_t getE_phoff() const;
  uint64_t getE_entry() const;
  uint32_t getMagicBytes() const;
  uint16_t getEi_class() const;
  uint16_t getEi_data() const;
  uint16_t getEi_osabi() const;

  void printFlag(uint32_t);

  std::map<uint16_t, std::string> getEtypeFlags() const;
  std::map<uint16_t, std::string> getEmachineFlags() const;
  std::map<uint16_t, std::string> getEclassFlags() const;
  std::map<uint16_t, std::string> getEdataFlags() const;
  std::map<uint16_t, std::string> getEiosabiFlags() const;

  enum flags { ETYPE = 0,
               EMACHINE = 1,
               ECLASS,
               EDATA, 
               EIOSABI };

 private:
  // Elfxx_Ehdr
  uint32_t magicBytes_u32;
  unsigned char e_ident[16];
  uint8_t ei_class_u8;
  uint8_t ei_data_u8;
  uint8_t ei_version_u8;
  uint8_t ei_osabi_u8;

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

  // Elfxx_Phdr
  uint32_t p_type_u32;
  uint32_t p_flags_u32;
  uint64_t p_offset_u64;
  uint64_t p_vaddr_u64;
  uint64_t p_paddr_u64;
  uint64_t p_filesz_u64;
  uint64_t p_memsz_u64;
  uint64_t p_align_u64;

  // Elfxx_Shdr
  std::vector<SectionHeader> sectionHeader;

  std::map<uint16_t, std::string> eclassFlags;   
  std::map<uint16_t, std::string> emachineFlags; 
  std::map<uint16_t, std::string> etypeFlags;    
  std::map<uint16_t, std::string> edataFlags;    
  std::map<uint16_t, std::string> eiosabiFlags;  
};

/*
sections:
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