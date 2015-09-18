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

#ifndef LIBSHAMBLES_CONNTRACK_H_
#define LIBSHAMBLES_CONNTRACK_H_


// ip addresses are struct in_addr (aka uint32_t in network byte order)
// ports are in network byte order

int32_t
conntrack_delete_ipv4_tcp(uint32_t orig_src_addr, uint32_t orig_dst_addr,
                          uint16_t orig_src_port, uint16_t orig_dst_port,
                          uint32_t repl_src_addr, uint32_t repl_dst_addr,
                          uint16_t repl_src_port, uint16_t repl_dst_port);

int32_t
conntrack_inject_ipv4_tcp(uint32_t orig_src_addr, uint32_t orig_dst_addr,
                          uint16_t orig_src_port, uint16_t orig_dst_port,
                          uint32_t repl_src_addr, uint32_t repl_dst_addr,
                          uint16_t repl_src_port, uint16_t repl_dst_port);

#endif
