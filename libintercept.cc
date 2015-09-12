#include "libintercept.h"

void swap_pkt_data(pkt_data_t const * const _in, pkt_data_t * const _out) {
  _out->src_addr = _in->dst_addr;
  _out->dst_addr = _in->src_addr;

  _out->src_port = _in->dst_port;
  _out->dst_port = _in->src_port;
  
  _out->seq = _in->ack;
  _out->ack = _in->seq;
}


void swap_pkt_data_inline(pkt_data_t * const _self){
  _self->src_addr = _self->src_addr ^ _self->dst_addr;
  _self->dst_addr = _self->src_addr ^ _self->dst_addr;
  _self->src_addr = _self->src_addr ^ _self->dst_addr;

  _self->src_port = _self->src_port ^ _self->dst_port;
  _self->dst_port = _self->src_port ^ _self->dst_port;
  _self->src_port = _self->src_port ^ _self->dst_port;

  _self->seq = _self->seq ^ _self->ack;
  _self->ack = _self->seq ^ _self->ack;
  _self->seq = _self->seq ^ _self->ack;
}


int8_t addr_in_subnet(uint32_t _addr, uint32_t _inner_addr, uint32_t _netmask) {
  if ( (_addr & _netmask) == (_inner_addr & _netmask) ) {
    return static_cast<int8_t>(true);
  }
  return static_cast<int8_t>(false);
}



