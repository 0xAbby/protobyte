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

### Unit testing

To help improve code quality, and assist in TDD (test driven development), the program is using GoogleTest Framework, to be able to run the unit test, installing libgtest is required. 

Installations steps are shown here: https://github.com/google/googletest/blob/main/googletest/README.md 


### Resources 

I found the following resources to be very helpful when writing this program:

- [Microsoft's PE Format documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

- [OSdev: ELF](https://wiki.osdev.org/ELF) 

- [Mach-O loader.h](https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html) 


- [Standard C++ Library reference](https://cplusplus.com/reference/)

- [C++ reference](https://en.cppreference.com/w/)

