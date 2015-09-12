#ifndef LIBINTERCEPT_LIBINTERCEPT_H_
#define LIBINTERCEPT_LIBINTERCEPT_H_

#include <stdint.h>

extern "C" {

typedef struct __attribute__((__packed__)) pkt_data {
  uint32_t src_addr;
  uint32_t dst_addr;

  uint16_t src_port;
  uint16_t dst_port;

  uint32_t seq;
  uint32_t ack;

  uint16_t msg_len;
  uint8_t* msg;
} pkt_data_t;

typedef struct forged_sockets {
  int outer_sock; // socket for outside host communication
  int inner_sock; // socket for inside host communication
} forged_sockets_t;

void swap_pkt_data(pkt_data_t const * const _in, pkt_data_t * const _out);
void swap_pkt_data_inline(pkt_data_t * const _self);

int8_t addr_in_subnet(uint32_t _addr, uint32_t _inner_addr, uint32_t _netmask);

int8_t intercept(forged_sockets_t* _out, pkt_data_t const * const _pd,
                 uint32_t const _outer_addr, uint32_t const _inner_addr);

int8_t intercept_teardown(pkt_data_t const * const _pd,
                          uint32_t const _outer_addr,
                          uint32_t const _inner_addr);

int8_t addr_in_subnet(uint32_t _addr, uint32_t _inner_addr,
                      uint32_t _netmask);

ssize_t send_forged_sockets(forged_sockets_t const * const _fst,
                           char const * const _path);

}

#endif