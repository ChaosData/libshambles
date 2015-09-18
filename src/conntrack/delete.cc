/*-
 * Copyright (c) 2015 [your name]
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Note: The code in this file links against libnetfilter_conntrack, which is
 * released under the terms of the GPLv2. While the code in this file is
 * released under non-GPLv2 terms, binary distributions including this code
 * must comply with the terms of the GPLv2.
 */

#include <stdio.h>
#include <stdint.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

int32_t conntrack_delete_ipv4_tcp(uint32_t orig_src_addr, uint32_t orig_dst_addr,
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

  struct nfct_handle *cth = nfct_open(CONNTRACK, 0);
  if (cth == NULL) {
    perror("nfct_open");
    return -2;
  }

  int res = nfct_query(cth, NFCT_Q_DESTROY, ct);
  nfct_close(cth);
  nfct_destroy(ct);

  if (res != 0) {
    perror("nfct_query");
    return -3;
  }

  return 1;
}
