#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

//#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <linux/netfilter/nf_conntrack_tcp.h> //for TCP_CONNTRACK_ESTABLISHED

int32_t conntrack_inject_ipv4_tcp(uint32_t orig_src_addr, uint32_t orig_dst_addr,
                              uint16_t orig_src_port, uint16_t orig_dst_port,
                              uint32_t repl_src_addr, uint32_t repl_dst_addr,
                              uint16_t repl_src_port, uint16_t repl_dst_port) {
  struct nf_conntrack *ct;

  ct = nfct_new();
  if (ct == NULL) {
    perror("nfct_new");
    return -1;
  }

  nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, AF_INET);
  nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, orig_src_addr);
  nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, orig_dst_addr);

  nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO, IPPROTO_TCP);
  nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, orig_src_port);
  nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, orig_dst_port);

  nfct_set_attr_u8(ct, ATTR_REPL_L3PROTO, AF_INET);
  nfct_set_attr_u32(ct, ATTR_REPL_IPV4_SRC, repl_src_addr);
  nfct_set_attr_u32(ct, ATTR_REPL_IPV4_DST, repl_dst_addr);

  nfct_set_attr_u8(ct, ATTR_REPL_L4PROTO, IPPROTO_TCP);
  nfct_set_attr_u16(ct, ATTR_REPL_PORT_SRC, repl_src_port);
  nfct_set_attr_u16(ct, ATTR_REPL_PORT_DST, repl_dst_port);

  nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_ESTABLISHED);
  nfct_set_attr_u32(ct, ATTR_TIMEOUT, 120);


  struct nfct_handle *cth = nfct_open(CONNTRACK, 0);
  if (cth == NULL) {
    perror("nfct_open");
    return -2;
  }

  int res = nfct_query(cth, NFCT_Q_CREATE, ct);
  nfct_close(cth);
  nfct_destroy(ct);

  if (res != 0) {
    perror("nfct_query");
    return -3;
  }

  return 1;
}
