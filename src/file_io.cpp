/**
 * @file file_io.cpp
 * @brief  Methods used for read/write operations on a given file
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#include "headers.h"

FileIO::FileIO() {}
FileIO::~FileIO() {}

/**
 * @brief A method to print out parsed information from a class object.
 *
 * @param fileObject A class object that will be either PE, ELF or MACHO, based
 * on the type the method will continue printing relevant information.
 *
 * @return none.
 */
FileIO::FileIO(std::string filename) {
  using namespace std;
  ifstream file(filename, ios::binary);
  uint32_t bytes = read_u32(file, true);

  file.seekg(0);
  if (uint16_t(bytes) == 0x5a4d) {
    // processing PE and print info
    PE pe;

    pe.init(filename);
    printPE(pe);
  } else if (bytes == 0x464c457f) {
    // processing ELF
    ELF elf;

    elf.init(filename);
    printELF(elf);
  } else if (bytes == 0xfeedfacf || bytes == 0xfeedface ||
             bytes == 0xcafebabe || bytes == 0xbebafeca) {
    // processing Mach-O
    MACHO mach_o;

    mach_o.init(filename);
    printMachO(mach_o);
  }
}

/**
 * @brief A Method to print out parsed information from a class object.
 *
* @param file A MACHO class object containing relevant information.
 *
 * @return none.
 */
void FileIO::printMachO(MACHO& file) const {
  using namespace std;

  cout << "Mach-O File: \n";
  cout << "  Magic bytes: \t0x" << hex << file.getMagicBytes() << endl;
  cout << "  CPU type; \t0x" << hex << file.getCputType() << endl;
  cout << "  CPU subtype: \t 0x" << hex << file.getCpuSubType() << endl;
  cout << "  File type: \t 0x" << hex << file.getFileType() << endl;
  cout << "  Number of load commands: \t0x" << hex << file.getNumLoadCommands() << endl;
  cout << "  Size of Load commands: \t0x" << hex << file.getSizeOfLoadCommand() << endl << endl;

  uint32_t numberOfLoadCommands = 4;
  for(uint32_t idx = 0; idx < numberOfLoadCommands ; idx++) { 
    cout << " command type: \t" << file.getLoadCommand()[idx].getCommand() << endl;
    cout << " command size: \t0x" << hex << file.getLoadCommand()[idx].getCommandSize() << endl;
    cout << " segment name: \t" << file.getLoadCommand()[idx].getSegmentName() << endl;
    cout << " VM Address: \t0x" << hex << file.getLoadCommand()[idx].getVMaddress() << endl;
    cout << " VM Size: \t0x" << hex <<  file.getLoadCommand()[idx].getVMSize() << endl;
    cout << " file offset: \t0x" << hex << file.getLoadCommand()[idx].getFileOffset() << endl;
    cout << " file size: \t0x" << hex << file.getLoadCommand()[idx].getFileSize() << endl << endl;

  }
  //  code directory info
  //  start of section headers

  // Fat mach-O file
  //  magic bytes
  //  fat_arch sections
  //  mach-o header
  //  
}

/**
 * @brief A Method to print out parsed information from a class object.
 *
 * @param file A PE class object containing relevant information.
 *
 * @return none.
 */
void FileIO::printPE(PE& file) const {
  using namespace std;

  uint32_t numberOfSections = file.getNumberOfSections();
  cout << "Parsed info: \n\n";

  // print magic bytes
  cout << "Magic bytes: 0x" << hex << file.getDosMagic() << endl;

  // print PE offset
  cout << "PE offset: 0x" << hex << file.getElfanew() << endl;

  // print number of section
  cout << "Number of sections: " << file.getNumberOfSections() << endl;

  // print characteristics
  cout << "Characteristics: 0x" << hex << file.getCharacteristics() << endl
       << endl;

  // print sections information
  for (uint32_t idx = 0; idx < numberOfSections; idx++) {
    cout << "Name: " << file.getSection(idx).getName() << endl;
    cout << " Virtual size: 0x" << hex << file.getSection(idx).getVirtualSize()
         << endl;
    cout << " Virtual Address: 0x" << hex
         << file.getSection(idx).getVirtualAddress() << endl;
    cout << " Characteristics: 0x" << hex
         << file.getSection(idx).getCharacteristics();
    cout << endl << endl;
  }
}

/**
 * @brief A Method to print out parsed information from a class object.
 *
* @param file A ELF class object containing relevant information.
 *
 * @return none.
 */
void FileIO::printELF(ELF& file) const {
  using namespace std;
  cout << "Magic bytes: \t0x" << hex << file.getMagicBytes() << " | "
       << file.getEclassFlags()[file.getEi_class()] << endl;
  cout << "byte order: \t" << file.getEdataFlags()[file.getEi_data()]
       << endl;
  cout << "OS ABI: \t" << file.getEiosabiFlags()[file.getEi_osabi()] << endl;
  cout << "Type: \t"   << file.getEtypeFlags()[file.getE_type()] << endl;
  cout << "Machine: \t" << file.getEmachineFlags()[file.getE_machine()] << endl;
  cout << "Entry Point: \t0x" << hex << file.getE_entry() << endl;
}

/**
 * @brief Reads unsigned 8 bits and returns them.
 *
 * @param in An std::ifstream object with file already opened.
 *
 * @return an 8 bit unsigned integer.
 */
uint8_t FileIO::read_u8(std::ifstream& in) {
  uint8_t value = 0;
  unsigned char ch[1] = {0};

  in.read(reinterpret_cast<char*>(ch), 1);
  value = ch[0];

  return value;
}

/**
 * @brief Reads unsigned 16 bits and returns them in little endian byte order.
 *
 * @param in An std::ifstream object with file already opened.
 * @param littleEnd Indicates byte order, True: Little end. False: Big end.
 *
 * @return a 16 bit unsigned integer.
 */
uint16_t FileIO::read_u16(std::ifstream& in, bool littleEnd) {
  uint16_t value = 0;
  unsigned char ch[3] = {0};

  in.read(reinterpret_cast<char*>(ch), 2);
  if (littleEnd) {
    value |= uint16_t(ch[1]) << 8;
    value |= uint16_t(ch[0]);
  } else {
    value |= uint16_t(ch[0]) << 8;
    value |= uint16_t(ch[1]);
  }
  return value;
}

/**
 * @brief Reads unsigned 32 bits and returns them in little endian byte order.
 *
 * @param in An std::ifstream object with file already opened.
 * @param littleEnd Indicates byte order, True: Little end. False: Big end.
 *
 * @return a 32 bit unsigned integer.
 */
uint32_t FileIO::read_u32(std::ifstream& in, bool littleEnd) {
  uint32_t value = 0;
  unsigned char ch[4] = {0};

  in.read(reinterpret_cast<char*>(ch), 4);
  if (littleEnd) {
    value |= uint32_t(ch[0]);
    value |= uint32_t(ch[1]) << 8;
    value |= uint32_t(ch[2]) << 16;
    value |= uint32_t(ch[3]) << 24;
  } else {
    value |= uint32_t(ch[0]) << 24;
    value |= uint32_t(ch[1]) << 16;
    value |= uint32_t(ch[2]) << 8;
    value |= uint32_t(ch[3]);
  }
  return value;
}

/**
 * @brief Reads unsigned 64 bits and returns them in little endian byte order.
 *
 * @param in An std::ifstream object with file already opened.
 * @param littleEnd Indicates byte order, True: Little end. False: Big end.
 *
 * @return a 64 bit unsigned integer.
 */
uint64_t FileIO::read_u64(std::ifstream& in, bool littleEnd) {
  uint64_t value = 0;
  unsigned char ch[9] = {0};

  in.read(reinterpret_cast<char*>(ch), 8);
  if (littleEnd) {
    value |= uint64_t(ch[0]);
    value |= uint64_t(ch[1]) << 8;
    value |= uint64_t(ch[2]) << 16;
    value |= uint64_t(ch[3]) << 24;
    value |= uint64_t(ch[4]) << 32;
    value |= uint64_t(ch[5]) << 40;
    value |= uint64_t(ch[6]) << 48;
    value |= uint64_t(ch[7]) << 56;
  } else {
    value |= uint64_t(ch[0]) << 56;
    value |= uint64_t(ch[1]) << 48;
    value |= uint64_t(ch[2]) << 40;
    value |= uint64_t(ch[3]) << 32;
    value |= uint64_t(ch[4]) << 24;
    value |= uint64_t(ch[5]) << 16;
    value |= uint64_t(ch[6]) << 8;
    value |= uint64_t(ch[7]);
  }
  return value;
}