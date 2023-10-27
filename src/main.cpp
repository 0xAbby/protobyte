//
// main.cpp:
//  binlyzer, a program for reading an executable's header info.
//
// Author:
//  Abdullah Ada 
//
#include "headers.h" 
#include "file_io.h"

int main(int argc, char *argv[]) {
  if( argc < 2 ) {
    printf("please supply at least One valid PE file\n");
    exit(1);
  }
  FileIO file(argc, argv);
  return 0;
}
