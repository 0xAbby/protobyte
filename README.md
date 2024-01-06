## binlyzer

A program to analyze PE, ELF and Mach-O files.

### Building and compiling
To build the program, simply clone and use 'make':
```
$ git clone https://github.com/0xAbby/binlyzer
$ cd binlyzer
$ make

...

$ ./binlyzer /path/to/executable-file
```

### Examples

Some examples parsing PE file:
```
$ ./binlyzer samples/pe/dbghelp.dll 
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
$ ./binlyzer samples/elf/lshw 
Magic bytes:    0x7f454c46 | 64bit (ELFCLASS64)
byte order:     Least Significant Byte (LSB)
OS ABI:         NONE
Type:   Dynamic / position independant ET_DYN
Machine:        64bit (EM_X86_64)
Entry Point:    0x1c1b0

$ ./binlyzer samples/elf/libstagefright_flacdec.so 
Magic bytes:    0x7f454c46 | 32bit (ELFCLASS32)
byte order:     Least Significant Byte (LSB)
OS ABI:         NONE
Type:   Dynamic / position independant ET_DYN
Machine:        ARM (EM_ARM)
Entry Point:    0x0
```


### Unit testing (optional)

To help improve code quality, and assist in TDD (test driven development), the program is using GoogleTest Framework, to be able to run the unit test, installing libgtest is required. 

Installations steps are shown here: https://github.com/google/googletest/blob/main/googletest/README.md 

To run unit tests, first the program needs to be compiled using the previous steps, then compile and run runTests:
```
$ cd unit_test
$ make
....
$ ./runTests
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

