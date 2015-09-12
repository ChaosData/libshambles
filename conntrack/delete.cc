/*

Modified from: https://raw.githubusercontent.com/threatstack/libnetfilter_conntrack/44dcf793ea4439978fbaae5b426912c4beb9425b/examples/nfct-mnl-del.c
License: GPLv2, https://raw.githubusercontent.com/threatstack/libnetfilter_conntrack/44dcf793ea4439978fbaae5b426912c4beb9425b/COPYING

*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <alloca.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <linux/netfilter/nf_conntrack_tcp.h>


int32_t conntrack_delete_ipv4_tcp(uint32_t orig_src_addr, uint32_t orig_dst_addr,
                              uint16_t orig_src_port, uint16_t orig_dst_port,
                              uint32_t repl_src_addr, uint32_t repl_dst_addr,
                              uint16_t repl_src_port, uint16_t repl_dst_port) {
  struct mnl_socket *nl;
  struct nlmsghdr *nlh;
  struct nfgenmsg *nfh;

  size_t mnl_socket_buffer_size = MNL_SOCKET_BUFFER_SIZE;
  char* buf = (char*)alloca(mnl_socket_buffer_size);
  memset(buf, 0, mnl_socket_buffer_size);

  uint32_t seq, portid;
  struct nf_conntrack *ct;
  int32_t ret;

  nl = mnl_socket_open(NETLINK_NETFILTER);
  if (nl == NULL) {
    perror("mnl_socket_open");
    return -1;
  }

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
    perror("mnl_socket_bind");
    return -2;
  }
  portid = mnl_socket_get_portid(nl);

  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE;
  nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
  nlh->nlmsg_seq = seq = time(NULL);

  nfh = (struct nfgenmsg *)mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
  nfh->nfgen_family = AF_INET;
  nfh->version = NFNETLINK_V0;
  nfh->res_id = 0;

  ct = nfct_new();
  if (ct == NULL) {
    perror("nfct_new");
    return -3;
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

  nfct_nlmsg_build(nlh, ct);
  nfct_destroy(ct);

  ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
  if (ret == -1) {
    perror("mnl_socket_recvfrom");

    return -4;
  }

  ret = mnl_socket_recvfrom(nl, buf, mnl_socket_buffer_size);
  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
    if (ret <= MNL_CB_STOP) {
      break;
    }
    ret = mnl_socket_recvfrom(nl, buf, mnl_socket_buffer_size);
  }
  if (ret == -1) {
    perror("mnl_socket_recvfrom");
    return -5;
  }

  mnl_socket_close(nl);

  return 1;
}
