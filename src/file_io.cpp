//
// file_io.c:
//    functions used for read/write operations on a given file
//
//    https://github.com/0xAbby/binlyzer
//
// Author:
//  Abdullah Ada
//
#include "headers.h"


// read_str(): reads a 'count' of characters from a file
// arguments: FILE stream to read from, count of characters to read
// returns: pointer to a string of characters.
char *read_str(FILE *in, int count) {
  char *ch_ptr = (char*) malloc(sizeof(char)*count);
  for(int i = 0; i < count; i++) {
    ch_ptr[i] = fgetc(in);
  }
  ch_ptr[strlen(ch_ptr)] = 0;
  return ch_ptr;
}

// read8_le(): reads an 8bit integer
// arguments: a file stream to read from
// return: an 8 bit integer
uint8_t  FileIO::read8_le(FILE *in) {
  return fgetc(in);
}

// read16_le(): reads an 16bit little-endian integer
// arguments: a file stream to read from
// return: an 16 bit integer
uint16_t  read16_le(FILE *in) {
  uint16_t value;
  value = fgetc(in);
  value |= (fgetc(in)<<8);
  return value;
}

// read32_le(): reads an 32bit little-endian integer
// arguments: a file stream to read from
// return: an 32 bit integer
uint32_t  read32_le(FILE *in) {
  uint32_t value;
  value = fgetc(in);
  value |= (fgetc(in)<<8);
  value |= (fgetc(in)<<16);
  value |= (fgetc(in)<<24);
  return value;
}

// read64_le(): reads an 64bit little-endian integer
// arguments: a file stream to read from
// return: an 64 bit integer
uint64_t  read64_le(FILE *in) {
  uint64_t value;
  value = (uint64_t)fgetc(in);
  value |= ((uint64_t)fgetc(in) <<8);
  value |= ((uint64_t)fgetc(in) <<16);
  value |= ((uint64_t)fgetc(in) <<24);
  value |= ((uint64_t)fgetc(in) <<32);
  value |= ((uint64_t)fgetc(in) <<40);
  value |= ((uint64_t)fgetc(in) <<48);
  value |= ((uint64_t)fgetc(in) <<54);

  return value;
}

FileIO::FileIO(int argc, char *argv[]) {

  for(int idx = 1; idx < argc; idx++) {
    in = fopen(argv[idx], "rb");
    if(in == NULL) {
      printf("Can't open '%s' file, exiting\n", argv[idx]);
      continue;
    }

    // read headers
    PE pe(in);



    //---------------------------/
    ///   C to c++
    // read_dos(in, &dosHeader);
    // read_pe(in, &dosHeader);

    // read_dataDir(in, &dosHeader);
    // read_sections(in, &dosHeader);
    // read_dataOffset(&dosHeader);
    // read_exportDir(in, &dosHeader);
    // read_importDir(in, &dosHeader);


    // test printing information
    //printf("showing file: %s \n\n", argv[idx]);

    // print_headers(&dosHeader);
    // print_dataTables(&dosHeader);
    // print_sections(&dosHeader);
    // print_exports(&dosHeader);
    // print_imports(&dosHeader);
  }
}

FileIO::~FileIO() {
  fclose(in);
}

