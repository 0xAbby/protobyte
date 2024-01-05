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
  if (argc < 2) {
    printf("please supply at least One valid PE file\n");
    exit(1);
  }
  FileIO fileObj(argv[1]);
  return 0;
}
