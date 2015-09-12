#ifndef LIBINTERCEPT_LIBINTERCEPT_H_
#define LIBINTERCEPT_LIBINTERCEPT_H_

#include <stdint.h>

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


typedef struct __attribute__((__packed__)) hook_data {
  uint32_t outer_addr;
  uint32_t inner_addr;

  uint16_t outer_port;
  uint16_t inner_port;

} hook_data_t;

void swap_pkt_data(pkt_data_t const * const _in, pkt_data_t * const _out);
void swap_pkt_data(pkt_data_t * const _self);

uint8_t addr_in_subnet(uint32_t _addr, uint32_t _inner_addr, uint32_t _netmask);

uint8_t intercept(pkt_data_t const * const _pd, uint32_t const _outer_addr, uint32_t const _inner_addr);



uint8_t intercept_setup(pkt_data_t const * const _pd, hook_data_t const * const _hd);
uint8_t intercept_teardown(pkt_data_t const * const _pd, hook_data_t const * const _hd);

#endif