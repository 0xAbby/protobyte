
![protobyte_microscope_icon](https://github.com/user-attachments/assets/8ac740fe-d577-456e-9ac4-3eb277b08802)


[![build](https://github.com/0xAbby/protobyte/actions/workflows/c_cpp.yml/badge.svg)](https://github.com/0xAbby/protobyte/actions/workflows/c_cpp.yml)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

## protobyte

A utility program for parsing header information found in executable for formats. Namely PE, ELF and Mach-O.

The project is on-going (still in progress), as I updated its features and expanding parsing capabilities.

### Building and compiling
To build the program, simply clone and use 'make':
```
~ $ git clone https://github.com/0xAbby/protobyte
~ $ cd protobyte/build
~/protobyte/build $ cmake ../
...
~/protobyte/build $ make -j
...
```

You will have by now two binaries to run, one is 'protobyte' and the other is 'runTests' for basic unit testing.

### Examples

Some examples parsing PE file:
```
~/protobyte/build $ ./protobyte samples/pe/dbghelp.dll 
Parsed info: 

Magic bytes: 0x5a4d
PE offset: 0x110
Number of sections: 8
Characteristics: 0x2022

Name: .text
 Virtual size: 0x1590de
 Virtual Address: 0x1000
 Characteristics: 0x60000020

Name: .rdata
 Virtual size: 0x58fda
 Virtual Address: 0x15b000
 Characteristics: 0x40000040

Name: .data
 Virtual size: 0x1f0bc
 Virtual Address: 0x1b4000
 Characteristics: 0xc0000040
...
```

Another example parsing an ELF file:
```
~/protobyte/build $ ./protobyte samples/elf/libstagefright_flacdec.so 
Magic bytes: 	0x7F454C46 | 64bit (ELFCLASS64)
byte order: 	Least Significant Byte (LSB)
OS ABI: 	NONE
Type: 	Dynamic / Position Independant ET_DYN
Machine: 	64bit (EM_X86_64)
Entry Point: 	0x1C1B0
Program headers offset : 	0x40
Program header entry size: 	0x38
total entries: 	0xD
Section header offset: 	0xE0D08
Section header entry size: 	0x40
total entries: 	0x1F

---------------------------------
Program section entries
programHeader[0]
  Type: 	PT_PHDR
  Flags: 	Read (PF_R)
  Offset: 	0x64
  Virtual Address: 	0x64
  Physical Address: 	0x64
  Segment file length: 	0x728
  Segment memory length: 	0x728
  Alignment: 	0x8

programHeader[1]
  Type: 	PT_INTERP
  Flags: 	Read (PF_R)
  Offset: 	0x792
  Virtual Address: 	0x792
  Physical Address: 	0x792
  Segment file length: 	0x28
  Segment memory length: 	0x28
  Alignment: 	0x1

programHeader[2]
  Type: 	PT_LOAD
  Flags: 	Read (PF_R)
  Offset: 	0x0
  Virtual Address: 	0x0
  Physical Address: 	0x0
  Segment file length: 	0x59304
  Segment memory length: 	0x59304
  Alignment: 	0x4096

programHeader[3]
  Type: 	PT_LOAD
  Flags: 	Read/Execute (PF_RX)
  Offset: 	0x61440
  Virtual Address: 	0x61440
  Physical Address: 	0x61440
  Segment file length: 	0x709237
  Segment memory length: 	0x709237
  Alignment: 	0x4096

[...output cut short for demo purposes....]
sectionHeader[16]
  Name: 	.text
  Type: 	SHT_PROGBITS
  flags: 	SHT_DYNAMIC
  Address: 	0x66672
  Offset: 	0x66672
  size: 	0x703990
  link: 	0x0
  info: 	0x0
  Address alignment: 	0x16
  Section size: 	0x0

sectionHeader[17]
  Name: 	.fini
  Type: 	SHT_PROGBITS
  flags: 	SHT_DYNAMIC
  Address: 	0x770664
  Offset: 	0x770664
  size: 	0x13
  link: 	0x0
  info: 	0x0
  Address alignment: 	0x4
  Section size: 	0x0

sectionHeader[18]
  Name: 	.rodata
  Type: 	SHT_PROGBITS
  flags: 	SHT_SYMTAB
  Address: 	0x774144
  Offset: 	0x774144
  size: 	0x36565
  link: 	0x0
  info: 	0x0
  Address alignment: 	0x32
  Section size: 	0x0

```

Example for parsing Mach-O format:
```
~/protobyte/build $ ./protobyte samples/mach-o/apfs_boot_util
Mach-O File: 
  Magic bytes: 	0xfeedfacf MACHO_64
  CPU type:    	0x100000c CPU_TYPE_ARM64
  CPU subtype: 	 0x80000002
  File type:   	 0x2 MACH_EXECUTE
  Number of load commands: 	0x5
  Size of Load commands:   	0x6b0

 command type: 	 SEGMENT_64
 command size: 	0x48
 segment name: 	__PAGEZERO
 VM Address:   	0x0
 VM Size:      	0x100000000
 file offset:  	0x0
 file size:    	0x0

 command type: 	 SEGMENT_64
 command size: 	0x1d8
 segment name: 	__TEXT
 VM Address:   	0x100000000
 VM Size:      	0x4000
 file offset:  	0x0
 file size:    	0x4000

 command type: 	 SEGMENT_64
 command size: 	0x138
 segment name: 	__DATA_CONST
 VM Address:   	0x100004000
 VM Size:      	0x4000
 file offset:  	0x4000
 file size:    	0x4000

 command type: 	 SEGMENT_64
 command size: 	0x98
 segment name: 	__DATA
 VM Address:   	0x100008000
 VM Size:      	0x4000
 file offset:  	0x8000
 file size:    	0x4000

 command type: 	 SEGMENT_64
 command size: 	0x48
 segment name: 	__LINKEDIT
 VM Address:   	0x10000c000
 VM Size:      	0x8000
 file offset:  	0xc000
 file size:    	0x5b20

```

### Unit testing (optional)

To help improve code quality, and assist in TDD (test driven development), the program is using GoogleTest Framework, to be able to run the unit test, installing libgtest is required. 

Installations steps are shown here: https://github.com/google/googletest/blob/main/googletest/README.md 

If you were able to compile and build the source code, then the unit testing binary will also have been compiled in the same build directory:
```
~/protobyte/build $ ./runTests

[==========] Running 13 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 13 tests from PETest
[ RUN      ] PETest.DosHeader
[       OK ] PETest.DosHeader (0 ms)
[ RUN      ] PETest.e_lfanew

......

[       OK ] PETest.dataVirtualAddress (0 ms)
[----------] 13 tests from PETest (2 ms total)

[----------] Global test environment tear-down
[==========] 13 tests from 1 test suite ran. (2 ms total)
[  PASSED  ] 13 tests.
```
If there are mistakes from the unit test it willbe dispalyed in the previous messages.

### Resources 

I found the following resources to be very helpful when writing this program:

- [Microsoft's PE Format documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

- [OSdev: ELF](https://wiki.osdev.org/ELF) 

- [Mach-O loader.h](https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html) 


- [Standard C++ Library reference](https://cplusplus.com/reference/)

- [C++ reference](https://en.cppreference.com/w/)

