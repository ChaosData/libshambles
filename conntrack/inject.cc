#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <linux/netfilter/nf_conntrack_tcp.h> //for TCP_CONNTRACK_ESTABLISHED

int32_t conntrack_inject_ipv4_tcp(uint32_t orig_src_addr, uint32_t orig_dst_addr,
                              uint16_t orig_src_port, uint16_t orig_dst_port,
                              uint32_t repl_src_addr, uint32_t repl_dst_addr,
                              uint16_t repl_src_port, uint16_t repl_dst_port) {
  struct mnl_socket *nl;
  struct nlmsghdr *nlh;
  struct nfgenmsg *nfh;

  size_t mnl_socket_buffer_size = MNL_SOCKET_BUFFER_SIZE;
  char* buf = (char*)alloca(mnl_socket_buffer_size);
  memset(buf, 0, mnl_socket_buffer_size);

  unsigned int seq, portid;
  struct nf_conntrack *ct;
  int ret;

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
  nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
  nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
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

  nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_ESTABLISHED);
  nfct_set_attr_u32(ct, ATTR_TIMEOUT, 60);


  struct nfct_handle *cth = nfct_open(CONNTRACK, 0);
  if (!cth) {
    puts("Can't open handler");
    return -44;
  }

  int res = nfct_query(cth, NFCT_Q_CREATE, ct);
  nfct_close(cth);
  nfct_destroy(ct);

/*
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
*/
  mnl_socket_close(nl);

  return 1;
}
