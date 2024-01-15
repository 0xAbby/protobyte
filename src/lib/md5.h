/**
 * md5.h: 
 * @brief  Function definitions for MD5 hashing algorithm.
 */
#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <cstring>
#include <string>
#include <iomanip>

/*  The following tests optimise behaviour on little-endian
    machines, where there is no need to reverse the byte order
    of 32 bit words in the MD5 computation.  By default,
    HIGHFIRST is defined, which indicates we're running on a
    big-endian (most significant byte first) machine, on which
    the byteReverse function in md5.c must be invoked. However,
    byteReverse is coded in such a way that it is an identity
    function when run on a little-endian machine, so calling it
    on such a platform causes no harm apart from wasting time.
    If the platform is known to be little-endian, we speed
    things up by undefining HIGHFIRST, which defines
    byteReverse as a null macro.  Doing things in this manner
    insures we work on new platforms regardless of their byte
    order.  */

#define HIGHFIRST

#if defined(__i386__) || defined(__x86_64__) || defined(__amd64__)
#undef HIGHFIRST
#endif

/*  On machines where "long" is 64 bits, we need to declare
    uint32 as something guaranteed to be 32 bits.  */

typedef uint32_t uint32;

struct MD5HasherContext
{
  uint32 buf[4];
  uint32 bits[2];
  unsigned char in[64];
};

/** 
 * @brief Creating a namespace for these functions 
 * */
class MD5Hasher {
public:
  MD5Hasher() {
    memset(&this->ctx, 0, sizeof(this->ctx));
  }
  ~MD5Hasher() {}

  void MD5Init();
  void MD5Update(unsigned char *buf, unsigned len);
  std::string MD5Final();

  int MD5FileContent(const std::string &file, std::string &md5);

private:
  struct MD5HasherContext ctx;
  void MD5Transform(uint32 buf[4], uint32 in[16]);
};

/*  Define CHECK_HARDWARE_PROPERTIES to have main.c verify
    byte order and uint32 settings.  */
#define CHECK_HARDWARE_PROPERTIES

#endif