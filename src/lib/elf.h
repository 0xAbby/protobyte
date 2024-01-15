/**
 * @file elf.h
 * @brief  Definitions and declarations for ELF module
 *
 * @ref https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#ifndef ELF_H
#define ELF_H

#include "../headers.h"


/**
 * @brief Section header class carries section-specific info. name, type, flags...etc
 */
class SectionHeader {
  public:
    void setSh_name(uint32_t);
    void setSh_name(std::string);
    void setSh_type(uint32_t);
    void setSh_flags(uint32_t);
    void setSh_addr(uint32_t);
    void setSh_offset(uint32_t);
    void setSh_size(uint32_t);
    void setSh_link(uint32_t);
    void setSh_info(uint32_t);
    void setSh_addralign(uint32_t);
    void setSh_entsize(uint32_t);

    uint32_t getSh_name();
    std::string getS_name();
    uint32_t getSh_type();
    uint32_t getSh_flags();
    uint32_t getSh_addr();
    uint32_t getSh_offset();
    uint32_t getSh_size();
    uint32_t getSh_link();
    uint32_t getSh_info();
    uint32_t getSh_addralign();
    uint32_t getSh_entsize();

  private:
    uint32_t sh_name_u32;
    std::string name;
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
 * @brief Program header class carries section-specific info, type, flags and offset...etc
 */
class ProgramHeader {
  public:
    void setP_type(uint32_t);
    void setP_flags(uint32_t);
    void setP_offset(uint64_t);
    void setP_vaddr(uint64_t);
    void setP_paddr(uint64_t);
    void setP_filesz(uint64_t);
    void setP_memsz(uint64_t);
    void setP_align(uint64_t);

    uint32_t getP_type();
    uint32_t getP_flags();
    uint64_t getP_offset();
    uint64_t getP_vaddr();
    uint64_t getP_paddr();
    uint64_t getP_filesz();
    uint64_t getP_memsz();
    uint64_t getP_align();

  private:
    uint32_t p_type_u32;
    uint32_t p_flags_u32;
    uint64_t p_offset_u64;
    uint64_t p_vaddr_u64;
    uint64_t p_paddr_u64;
    uint64_t p_filesz_u64;
    uint64_t p_memsz_u64;
    uint64_t p_align_u64;
};

/**
 * @brief ELF class handles parsing specific ELF format. Magic bytes, header info...etc
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
  std::string getSectionHeaderName(uint32_t, uint32_t, std::ifstream&);

  unsigned char* getE_ident();
  uint16_t getE_type() const;
  uint16_t getE_machine() const;
  uint64_t getE_phoff() const;
  uint64_t getE_entry() const;
  uint32_t getMagicBytes() const;
  uint16_t getEi_class() const;
  uint16_t getEi_data() const;
  uint16_t getEi_osabi() const;
  uint64_t getE_shoff();
  uint16_t getE_phentsize();
  uint16_t getE_phnum();
  uint16_t getE_shentsize();
  uint16_t getE_shnum();

  void printFlag(uint32_t, uint32_t);

  std::map<uint16_t, std::string> getEtypeFlags() const;
  std::map<uint16_t, std::string> getEmachineFlags() const;
  std::map<uint16_t, std::string> getEclassFlags() const;
  std::map<uint16_t, std::string> getEdataFlags() const;
  std::map<uint16_t, std::string> getEiosabiFlags() const;
  std::vector<SectionHeader> getSectionHeaders() const;

  // flags/machine are "bytes to string" mapping 
  // that will represent specific bytes values and their
  // meaning in a human readable string.
  enum flags { ETYPE = 0,
               EMACHINE = 1,
               ECLASS,
               EDATA, 
               EIOSABI,
               SECTIONTYPE,
               SECTIONFLAG,
               PROGRAMTYPE,
               PROGRAMFLAG};
  enum machine {EM_X86_64 = 50, EM_ARM = 41, EM_386 = 3  };

 private:
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

  
  std::vector<ProgramHeader> programHeader;
  std::vector<SectionHeader> sectionHeader;
  

  std::map<uint16_t, std::string> eclassFlags;   
  std::map<uint16_t, std::string> emachineFlags; 
  std::map<uint16_t, std::string> etypeFlags;    
  std::map<uint16_t, std::string> edataFlags;    
  std::map<uint16_t, std::string> eiosabiFlags;  

  std::map<uint32_t, std::string> sectionHeaderType_m;
  std::map<uint32_t, std::string> sectionHeaderFlag_m;
  std::map<uint32_t, std::string> programHeaderType_m;
  std::map<uint32_t, std::string> programHeaderFlag_m;  
};

#endif