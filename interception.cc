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


//constexpr static char const dnat[] = "iptables -t nat -%c PREROUTING -m state --state INVALID,NEW,RELATED,ESTABLISHED -p tcp -d %s --dport %hu -j DNAT --to-destination %s:%hu";
//constexpr static uint16_t dnat_size = sizeof(dnat)    - 1                                                                     + 14         + 2                        + 14 + 2;


//constexpr static char const snat[] = "iptables -t nat -%c POSTROUTING -m state --state INVALID,NEW,RELATED,ESTABLISHED -p tcp -d %s --dport %hu -j SNAT --to-source %s:%hu";
//constexpr static uint16_t snat_size = sizeof(snat)    - 1                                                                      + 14         + 2                   + 14 + 2;


constexpr static char const snat2[] = "iptables -t nat -%c POSTROUTING -m state --state INVALID,NEW,RELATED,ESTABLISHED -p tcp -s %s --sport %hu -d %s --dport %hu -j SNAT --to-source %s:%hu";
constexpr static uint16_t snat2_size = sizeof(snat2)    - 1                                                                     + 14         + 2  + 14         + 2                   + 14 + 2;


                                                  //   _pd->src_addr _pd->dst_addr        _pd->src_port       _pd->dst_port       _pd->dst_port        _pd->src_port        _pd->dst_addr  _hd->outer_addr
constexpr static char const conntrack[] = "conntrack -%s --orig-src %s --orig-dst %s -p tcp --orig-port-src %hu --orig-port-dst %hu --reply-port-src %hu --reply-port-dst %hu --reply-src %s --reply-dst %s";
constexpr static uint16_t conntrack_size = sizeof(conntrack)-1    + 13          + 13                        + 3                 + 3                  + 3                  + 3           + 13           + 13;
//constexpr static uint16_t conntrack_size = sizeof(conntrack)    + 14          + 14                        + 2                 + 2                  + 2                  + 2           + 14           + 14;

                                                  //   _pd->src_addr _pd->dst_addr        _pd->src_port       _pd->dst_port       _pd->dst_port        _pd->src_port        _pd->dst_addr  _hd->outer_addr
constexpr static char const conntrackTS[] = "conntrack -%s --orig-src %s --orig-dst %s -p tcp --orig-port-src %hu --orig-port-dst %hu --reply-port-src %hu --reply-port-dst %hu --reply-src %s --reply-dst %s --timeout 20 --state ESTABLISHED";
constexpr static uint16_t conntrackTS_size = sizeof(conntrackTS)-1    + 13          + 13                        + 3                 + 3                  + 3                  + 3           + 13           + 13;


//constexpr static char const conntrackD = "conntrack -D --orig-src 192.168.108.10 --orig-dst 173.2.43.115 -p tcp --orig-port-src 53757 --orig-port-dst 53 --reply-port-src 53 --reply-port-dst 53757 --reply-src 173.2.43.115 --reply-dst 10.133.110.188";


uint8_t intercept(pkt_data_t const * const _pd, hook_data_t const * const _hd) {
  pkt_data_dump(_pd);
  hook_data_dump(_hd);


  struct tcp_state *fake_server;
  struct tcp_state *fake_client;

  fake_server = forge_socket_get_default_state();
  fake_client = forge_socket_get_default_state();
  
  int client_sock = socket(AF_INET, SOCK_FORGE, 0);
  int server_sock = socket(AF_INET, SOCK_FORGE, 0);

// orig
//  fake_client->src_ip = _hd->outer_addr; //inet_addr("10.133.110.188");
// reverse
//  fake_client->src_ip = _hd->inner_addr; //inet_addr("10.133.110.188");
  fake_client->src_ip = _hd->outer_addr; //inet_addr("10.133.110.188");
  fake_client->dst_ip = _pd->dst_addr;
  fake_client->sport = _pd->src_port;//_hd->outer_port;//_pd->src_port; // this one needs to be handled carefully
  fake_client->dport = _pd->dst_port;
  fake_client->seq = ntohl(_pd->seq);
  fake_client->ack = ntohl(_pd->ack);
  fake_client->snd_una = ntohl(_pd->seq);

// orig
//  fake_server->src_ip = _hd->inner_addr;//inet_addr("192.168.108.1");
// reverse
//  fake_server->src_ip = _hd->outer_addr;//inet_addr("192.168.108.1");
  //fake_server->src_ip = _pd->dst_addr;
  // if fake_server->src_ip is _pd->dst_addr, then the packets will be sent right,
  // but the interceptor won't be able to process that the response packets are for it

  fake_server->src_ip = _hd->inner_addr; // need to try and setup conntrack for this
  fake_server->dst_ip = _pd->src_addr;
//  fake_server->sport = _hd->inner_port;//htons(4450);
  fake_server->sport = _pd->dst_port;//htons(4450);
  fake_server->dport = _pd->src_port;
  fake_server->seq = ntohl(_pd->ack);
  fake_server->ack = ntohl(_pd->seq);
  fake_server->snd_una = ntohl(_pd->ack);

  // TODO: fake server src=inner, fake client src=outer

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
  //system("sh ./redir.sh A");
  puts("\n");
  system("conntrack -L");
  puts("\n");

  char inner_addr[16] = {0};
  inet_ntoa_r(inner_addr, _hd->inner_addr);

  char outer_addr[16] = {0};
  inet_ntoa_r(outer_addr, _hd->outer_addr);


  char dst_addr[16] = {0};
  inet_ntoa_r(dst_addr, _pd->dst_addr);

  char src_addr[16] = {0};
  inet_ntoa_r(src_addr, _pd->src_addr);


  // replace with specific contrack deletion
  puts("\n");
  //system("conntrack -F");

  puts("Injecting new conntrack entries:");
  char conntrackI_command[conntrackTS_size] = {0};
/*  snprintf((char*)conntrackI_command, conntrackTS_size, conntrackTS, "I",
      src_addr, //--orig-src
      dst_addr, //--orig-dst
      ntohs(_pd->src_port), //--orig-port-src
      ntohs(_pd->dst_port), //--orig-port-dst

      ntohs(_pd->dst_port), //--reply-port-src
      ntohs(_pd->src_port), //--reply-port-dst
      "10.133.110.188", //--reply-src
      dst_addr //--reply-dst
  );
  printf("# %s\n", conntrackI_command);
  system(conntrackI_command);
*/
  puts("Deleting old conntrack entry:");
  char conntrackD_command[conntrack_size] = {0};
  snprintf((char*)conntrackD_command, conntrack_size, conntrack, "D",
      src_addr, dst_addr,
      ntohs(_pd->src_port), ntohs(_pd->dst_port), ntohs(_pd->dst_port),
      ntohs(_pd->src_port),
      dst_addr, "10.133.110.188" //outer_addr
  );
  printf("# %s\n", conntrackD_command);
  system(conntrackD_command);
  system("conntrack -L");


  puts("\n");



  //char dnat_command[dnat_size] = {0};
//  snprintf((char*)dnat_command, dnat_size, dnat, 'A', dst_addr, ntohs(_pd->dst_port), inner_addr, ntohs(_hd->inner_port));
  //snprintf((char*)dnat_command, dnat_size, dnat, 'A', dst_addr, ntohs(_pd->dst_port), inner_addr, ntohs(_pd->src_port));
  //printf("# %s\n", dnat_command);
  //system(dnat_command);
  //Not needed


  //char snat_command[snat_size] = {0};
  //snprintf(snat_command, snat_size, snat, 'A', src_addr, ntohs(_pd->src_port), dst_addr, ntohs(_pd->dst_port));
  //printf("# %s\n", snat_command);
  //system(snat_command);
  //may be needed (very heavy handed though)

  char snat2_command[snat2_size] = {0};
  snprintf(snat2_command, snat2_size, snat2, 'A', inner_addr, ntohs(_pd->dst_port), src_addr, ntohs(_pd->src_port), dst_addr, ntohs(_pd->dst_port));
  printf("# %s\n", snat2_command);
  system(snat2_command);
  

/*
  snprintf((char*)conntrackI_command, conntrackTS_size, conntrackTS, "I",
      src_addr, //--orig-src
      dst_addr, //--orig-dst
      ntohs(_pd->src_port), //--orig-port-src
      ntohs(_pd->dst_port), //--orig-port-dst

      ntohs(_pd->src_port), //--reply-port-src
      ntohs(_pd->dst_port), //--reply-port-dst
      src_addr, //--reply-src
      inner_addr //--reply-dst
  );
  printf("# %s\n", conntrackI_command);
  system(conntrackI_command);
*/

/*  
  snprintf((char*)conntrackI_command, conntrackTS_size, conntrackTS, "I",
      inner_addr, //--orig-src
      src_addr, //--orig-dst
      ntohs(_pd->dst_port), //--orig-port-src
      ntohs(_pd->src_port), //--orig-port-dst

      ntohs(_pd->src_port), //--reply-port-src
      ntohs(_pd->dst_port), //--reply-port-dst
      src_addr, //--reply-src
      dst_addr //--reply-dst
  );
  printf("# %s\n", conntrackI_command);
  system(conntrackI_command);
*/

/*
  snprintf((char*)conntrackI_command, conntrackTS_size, conntrackTS, "I",
      src_addr, //--orig-src
      dst_addr, //--orig-dst
      ntohs(_pd->src_port), //--orig-port-src
      ntohs(_pd->dst_port), //--orig-port-dst

      ntohs(_pd->src_port), //--reply-port-src
      ntohs(_pd->dst_port), //--reply-port-dst
      src_addr, //--reply-src
      dst_addr //--reply-dst
  );
  printf("# %s\n", conntrackI_command);
  system(conntrackI_command);
*/

  //TODO: need to run iptables stuff
  // and have the fake client/server sockets be locally bound on different ports



  puts("\n");
  printf("sending/receiving...\n");
  printf("server_sock: %x, client_sock: %x\n", server_sock, client_sock);

  //char buf[1024];
  int r = 0;
  //r = recv(client_sock, buf, sizeof(buf), 0);
  //printf("GOT: %s\n",buf);

  //char *msg2client = "hello world\n";
  //r = send(client_sock, msg2client, strlen(msg2client), 0);
  //puts("1");


  /*char rec1[1024] = {0};
  r = recv(server_sock, rec1, sizeof(rec1), 0);
  puts(rec1);*/

  char imsg2[] = "GOODBYE CLIENT!\n";
  r = send(client_sock, imsg2, strlen(imsg2), 0);
  printf("client send: %d\n", r);

  char imsg[] = "FAREWELL SERVER!\n";
  r = send(server_sock, imsg, strlen(imsg), 0);
  printf("server send: %d\n", r);



  system("conntrack -L");




  char rec[1024] = {0};




  // printf("# %s\n", conntrackI_command);
  // system(conntrackI_command);

  puts("recv'ing from server:");
  r = recv(server_sock, rec, sizeof(rec), 0);
  printf("GOT (server): %s\n", rec);
  close(server_sock);

  puts("recv'ing from client:");
  r = recv(client_sock, rec, sizeof(rec), 0);
  printf("GOT (client): %s\n", rec);
  close(client_sock);




  puts("\n");
  system("conntrack -L");
  puts("\n");

//  r = recv(client_sock, rec, sizeof(rec), 0);
//  printf("GOT (client): %s\n", rec);





  //close(client_sock);
  sleep(1);

  //snprintf((char*)dnat_command, dnat_size, dnat, 'D', dst_addr, ntohs(_pd->dst_port), inner_addr, ntohs(_hd->inner_port));
  //printf("# %s\n", dnat_command);
  //system(dnat_command);
  //snprintf(snat_command, snat_size, snat, 'D', src_addr, ntohs(_pd->src_port), dst_addr, ntohs(_pd->dst_port));
  //printf("# %s\n", snat_command);
  //system(snat_command);

  snprintf(snat2_command, snat2_size, snat2, 'D', inner_addr, ntohs(_pd->dst_port), src_addr, ntohs(_pd->src_port), dst_addr, ntohs(_pd->dst_port));
  printf("# %s\n", snat2_command);
  system(snat2_command);
  



/*  char rec[1024] = {0};
  r = recv(client_sock, rec, sizeof(rec), 0);
  puts(rec);
*/
//  r = send(server_sock, imsg, strlen(imsg), 0);
//  printf("%d\n", r);

//  r = send(client_sock, imsg2, strlen(imsg2), 0);
//  printf("%d\n", r);

  puts("\n");
  system("conntrack -L");
  puts("\n");


  free(fake_server);
  free(fake_client);

  return 0;
}


