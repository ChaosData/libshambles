#ifndef LIBSHAMBLES_UTIL_H_
#define LIBSHAMBLES_UTIL_H_

#include <stdint.h>

#include "shambles.h"
#include "libforge_socket_override/libforge_socket.h"

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

void hexdump(uint8_t const * const _data, uint16_t const _data_len);
void tcp_state_dump(tcp_state_t const * const _st);
void pkt_data_dump(pkt_data_t const * const _pd);
//void hook_data_dump(hook_data_t const * const _hdt);

#endif
