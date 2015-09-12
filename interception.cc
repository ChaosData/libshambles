#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>
#include <pcap.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include "util.h"
#include "libintercept.h"
#include "libforge_socket/libforge_socket.h"

#include "conntrack.h"

constexpr static char const dnat[] = "iptables -t nat -%c PREROUTING -m state --state INVALID,NEW,RELATED,ESTABLISHED -p tcp -s %s --sport %hu -d %s --dport %hu -j DNAT --to-destination %s:%hu";
constexpr static uint16_t dnat_size = sizeof(dnat)    - 1                                                                     + 14         + 3  + 14         + 3                        + 14 + 3;


constexpr static char const snat[] = "iptables -t nat -%c POSTROUTING -m state --state INVALID,NEW,RELATED,ESTABLISHED -p tcp -s %s --sport %hu -d %s --dport %hu -j SNAT --to-source %s:%hu";
constexpr static uint16_t snat_size = sizeof(snat)    - 1                                                                      + 14         + 3  + 14         + 3                   + 14 + 3;


constexpr static char const conntrackD[] = "conntrack -D --orig-src %s --orig-dst %s -p tcp --orig-port-src %hu --orig-port-dst %hu --reply-port-src %hu --reply-port-dst %hu --reply-src %s --reply-dst %s";
constexpr static uint16_t conntrackD_size = sizeof(conntrackD)    + 13          + 13                        + 3                 + 3                  + 3                  + 3           + 13           + 13;


constexpr static char const conntrackI[] = "conntrack -I --orig-src %s --orig-dst %s -p tcp --orig-port-src %hu --orig-port-dst %hu --reply-port-src %hu --reply-port-dst %hu --reply-src %s --reply-dst %s --timeout 60 --state ESTABLISHED";
constexpr static uint16_t conntrackI_size = sizeof(conntrackI)    + 13          + 13                        + 3                 + 3                  + 3                  + 3           + 13           + 13;



uint8_t intercept(pkt_data_t const * const _pd, uint32_t const _outer_addr, uint32_t const _inner_addr) {
  pkt_data_dump(_pd);

  struct tcp_state *fake_server;
  struct tcp_state *fake_client;

  fake_server = forge_socket_get_default_state();
  fake_client = forge_socket_get_default_state();
  
  int client_sock = socket(AF_INET, SOCK_FORGE, 0);
  int server_sock = socket(AF_INET, SOCK_FORGE, 0);


  fake_client->src_ip = _outer_addr;
  fake_client->dst_ip = _pd->dst_addr;
  fake_client->sport = _pd->src_port;
  fake_client->dport = _pd->dst_port;
  fake_client->seq = ntohl(_pd->seq);
  fake_client->ack = ntohl(_pd->ack);
  fake_client->snd_una = ntohl(_pd->seq);

  fake_server->src_ip = _inner_addr;
  fake_server->dst_ip = _pd->src_addr;
  fake_server->sport = _pd->dst_port;
  fake_server->dport = _pd->src_port;
  fake_server->seq = ntohl(_pd->ack);
  fake_server->ack = ntohl(_pd->seq);
  fake_server->snd_una = ntohl(_pd->ack);

  if (forge_socket_set_state(client_sock, fake_server) != 0) {
    printf("fail1\n");
    close(client_sock);
    return 2;
  }


  if (forge_socket_set_state(server_sock, fake_client) != 0) {
    printf("fail2\n");
    close(server_sock);
    return 3;
  }



  sleep(1);

  char inner_addr_str[16] = {0};
  inet_ntoa_r(inner_addr_str, _inner_addr);

  char outer_addr_str[16] = {0};
  inet_ntoa_r(outer_addr_str, _outer_addr);


  char dst_addr[16] = {0};
  inet_ntoa_r(dst_addr, _pd->dst_addr);

  char src_addr[16] = {0};
  inet_ntoa_r(src_addr, _pd->src_addr);


  puts("Deleting old conntrack entry:");

  int32_t delret = conntrack_delete_ipv4_tcp(_pd->src_addr, _pd->dst_addr,
                                             _pd->src_port, _pd->dst_port,
                                             _pd->dst_port, _pd->src_port,
//                                             _pd->dst_addr, _pd->src_addr);
                                             _pd->dst_addr, _outer_addr);
  if (delret != 1) {
    printf("%d\n", delret);
    close(server_sock);
    close(client_sock);
    exit(1);
  }

  puts("Injecting new conntrack entry:");

  char conntrackI_command[conntrackI_size] = {0};

  int32_t injret = conntrack_inject_ipv4_tcp(_outer_addr, _pd->dst_addr,
                                             _pd->src_port, _pd->dst_port,
                                             _pd->dst_addr, _outer_addr,
                                             _pd->dst_port, _pd->src_port);
  if (injret != 1) {
    printf("%d\n", injret);
    close(server_sock);
    close(client_sock);
    exit(1);
  }




  char dnat_command[dnat_size] = {0};
  snprintf(dnat_command, dnat_size, dnat, 'A', src_addr, ntohs(_pd->src_port), dst_addr, ntohs(_pd->dst_port), inner_addr_str, ntohs(_pd->dst_port));
  printf("# %s\n", dnat_command);
  system(dnat_command);



  char snat_command[snat_size] = {0};
  snprintf(snat_command, snat_size, snat, 'A', inner_addr_str, ntohs(_pd->dst_port), src_addr, ntohs(_pd->src_port), dst_addr, ntohs(_pd->dst_port));
  printf("# %s\n", snat_command);
  system(snat_command);
  


  printf("sending/receiving...\n");
  printf("server_sock: %x, client_sock: %x\n", server_sock, client_sock);

  int r = 0;
  char rec[1028] = {0};

  puts("recv'ing from server:");
  r = recv(server_sock, rec, sizeof(rec), 0);
  printf("GOT (server): %s\n", rec);
  char imsg[] = "FAREWELL SERVER!\n";
  r = send(server_sock, imsg, strlen(imsg), 0);
  printf("server send: %d\n", r);
  close(server_sock);

  memset(rec, 0, sizeof(rec));

  puts("recv'ing from client:");
  r = recv(client_sock, rec, sizeof(rec), 0);
  printf("GOT (client): %s\n", rec);
  char imsg2[] = "GOODBYE CLIENT !!\n";
  r = send(client_sock, imsg2, strlen(imsg2), 0);
  printf("client send: %d\n", r);

  close(client_sock);



  sleep(1);


  snprintf(dnat_command, dnat_size, dnat, 'D', src_addr, ntohs(_pd->src_port), dst_addr, ntohs(_pd->dst_port), inner_addr_str, ntohs(_pd->dst_port));
  printf("# %s\n", dnat_command);
  system(dnat_command);

  snprintf(snat_command, snat_size, snat, 'D', inner_addr_str, ntohs(_pd->dst_port), src_addr, ntohs(_pd->src_port), dst_addr, ntohs(_pd->dst_port));
  printf("# %s\n", snat_command);
  system(snat_command);
  
  free(fake_server);
  free(fake_client);

  return 0;
}


