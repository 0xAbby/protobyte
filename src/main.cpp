/**
 * @file main.cpp
 * @brief  binlyzer, a program for reading an executable's header info.
 *
 *  https://github.com/0xAbby/binlyzer
 *
 * @author Abdullah Ada
 */
#include "headers.h"

int main(int argc, char* argv[]) {
  try {
    if (argc < 2) {
      printf("please supply at least One valid PE file\n");
      exit(1);
    }
    FileIO file(argv[1]);
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n"; // exepction.. 
  }
  return 0;
}
