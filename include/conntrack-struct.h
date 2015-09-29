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

#ifndef LIBSHAMBLES_CONNTRACK_STRUCT_H_
#define LIBSHAMBLES_CONNTRACK_STRUCT_H_

#include <stdint.h>
#include <arpa/inet.h>

struct ConntrackOption { };
struct ConntrackInjectOption : ConntrackOption { };
struct ConntrackDeleteOption : ConntrackOption { };
struct ConntrackWatOption : ConntrackOption { };

struct Conntrack {
  using Inject = ConntrackInjectOption;
  using Delete = ConntrackDeleteOption;
  using Wat = ConntrackWatOption;
};

typedef union addr {
  struct in_addr ipv4_addr;
  struct in6_addr ipv6_addr;
} addr_t;

struct nf_ct {
  //struct nfct_tuple_head  head;
  addr_t h_s;
  addr_t h_d;

  uint8_t h_3p; //ATTR_ORIG_L3PROTO
  uint8_t h_p;
  uint16_t h_4s;
  uint16_t h_4d;
  uint32_t h_bits[3];

  //struct __nfct_tuple     repl;
  addr_t r_s;
  addr_t r_d;  
  uint8_t r_3p;
  uint8_t r_p;
  uint16_t r_4s;
  uint16_t r_4d;

  //struct __nfct_tuple     master;
  addr_t m_s;
  addr_t m_d;  
  uint8_t m_3p;
  uint8_t m_p;
  uint16_t m_4s;
  uint16_t m_4d;

  uint32_t to;
  uint32_t mk;
  uint32_t sm;
  uint32_t st;
  uint32_t us;
  uint32_t id;
  uint16_t zn;

  char nfct_helper_name[16];

  char *nfct_secctx;

  //union __nfct_protoinfo  protoinfo;
  uint8_t nfct_pinfo[16];

  //struct __nfct_counters  counters[__DIR_MAX];
  uint64_t nfct_ctrs_pkts_0;
  uint64_t nfct_ctrs_byts_0; 

  uint64_t nfct_ctrs_pkts_1;
  uint64_t nfct_ctrs_byts_1;

  //struct __nfct_nat       snat;
  uint32_t snat_min_ipv4_addr;
  uint32_t snat_max_ipv4_addr;
  uint16_t snat_4min;
  uint16_t snat_4max;

  //struct __nfct_nat       dnat;
  uint32_t dnat_min_ipv4_addr;
  uint32_t dnat_max_ipv4_addr;
  uint16_t dnat_4min;
  uint16_t dnat_4max;

  uint32_t nfct_natseq_corrp_0;
  uint32_t nfct_natseq_offb_0;
  uint32_t nfct_natseq_offa_0;

  uint32_t nfct_natseq_corrp_1;
  uint32_t nfct_natseq_offb_1;
  uint32_t nfct_natseq_offa_1;

  uint64_t ts_b;
  uint64_t ts_e;

  void *nfct_helper_info;
  size_t nfct_helper_info_len;

  void *nfct_connlabels;
  void *nfct_connlabels_mask;

};

#endif
