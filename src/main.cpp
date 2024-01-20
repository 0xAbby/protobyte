/**
 * @file main.cpp
 * @brief  binlyzer, a program for reading an executable's header info.
 *
 * @ref https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#include "headers.h"

int main(int argc, char* argv[]) {
  try {
    if (argc < 2) {
      std::cout << "please supply at least One valid PE file\n";
      return -1;
    }
    FileIO file(argv[1]);
  }
  catch (std::exception& except)
  {
    std::cerr << "Exception: " << except.what() << "\n";
  }
  return 0;
}
