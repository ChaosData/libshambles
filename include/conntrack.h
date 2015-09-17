#ifndef LIBINTERCEPT_CONNTRACK_H_
#define LIBINTERCEPT_CONNTRACK_H_


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