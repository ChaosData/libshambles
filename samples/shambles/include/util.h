#ifndef LIBSHAMBLES_UTIL_H_
#define LIBSHAMBLES_UTIL_H_

#include <stdint.h>

#ifdef DEBUG
  #define DEBUG_printf(...) fprintf(stderr, __VA_ARGS__)
#else
  #define DEBUG_printf(...) (void)0
#endif

uint8_t parse_ipv4(const char* str, uint64_t len);

/**
* Usage:
*   char buf[16];
*   inet_htoa_r(buf, ntohl(inet_addr("1.2.3.4")));
*/
char* inet_htoa_r(char* buf, uint32_t haddr);


/**
* Usage:
*   char buf[16];
*   inet_ntoa_r(buf, inet_addr("1.2.3.4"));
*/
char* inet_ntoa_r(char* buf, uint32_t haddr);


#endif
