/**
    sha1.h:
        Functions defintions for the SHA1 hashing algorithm.

    100% Public Domain.
    Original C Code
        @author Steve Reid <steve@edmweb.com>
    Small changes to fit into bglibs
        @author Bruce Guenter <bruce@untroubled.org>
    Translation to simpler C++ Code
        @author Volker Diels-Grabsch <v@njh.eu>
    Safety fixes
        @author Eugene Hopkinson <slowriot at voxelstorm dot com>
    Header-only library
        @author Zlatko Michailov <zlatko@michailov.org>
*/
#ifndef SHA1_H
#define SHA1_H

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

class SHA1 {
 public:
  SHA1();
  void update(const std::string& s);
  void update(std::istream& is);
  std::string final();
  static std::string from_file(const std::string& filename);

 private:
  uint32_t digest[5];
  std::string buffer;
  uint64_t transforms;
};

#endif