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


#include "libintercept.h"
#include "util.h"

int main(int argc, char const *argv[]) {


  if (argc != 4) {
    fputs("Usage: ./mitmd <public IP> <internal IP> <internal netmask>\n", stderr);
    return 1;
  }

  if ( parse_ipv4(argv[1], strlen(argv[1])) != 0 ) {
    fprintf(stderr, "Invalid <public IP> value: %s\n", argv[1]);
    return 2;
  }

  if ( parse_ipv4(argv[2], strlen(argv[2])) != 0 ) {
    fprintf(stderr, "Invalid <internal IP> value: %s\n", argv[2]);
    return 2;
  }

  if ( parse_ipv4(argv[3], strlen(argv[3])) != 0 ) {
    fprintf(stderr, "Invalid <internal netmask> value: %s\n", argv[3]);
    return 2;
  }

  int ret = 0;

  int sock;
  struct sockaddr_in sin;
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    perror("socket");
    return -1;
  }
  
  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port        = htons(5555);

  int val = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

  if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("bind");
    return -1;
  }

  if (listen(sock, 5) < 0) {
    perror("listen");
    return -1;
  }
  printf("listening...\n");

  socklen_t len = sizeof(sin);
  int sock_recv = accept(sock, (struct sockaddr *)&sin, &len);
  if (sock_recv < 0) {
    perror("accept");
    return 1;
  }
  printf("got connection from %s\n", inet_ntoa(sin.sin_addr));
  
  uint64_t r;


  pkt_data_t* pdt = (pkt_data_t*)calloc(1, sizeof(pkt_data_t));
  if ( pdt == nullptr ) {
    return -1;
  }

  hook_data_t* hdt = (hook_data_t*)calloc(1, sizeof(hook_data_t));
  if ( hdt == nullptr ) {
    return -2;
  }

/* orig */
  uint32_t outer_addr = inet_addr(argv[1]);
  uint32_t inner_addr = inet_addr(argv[2]);
  uint32_t netmask = inet_addr(argv[3]);

  printf("outer: %x, inner: %x\n", outer_addr, inner_addr);
  uint32_t msg_len = 0;

  r = recv(sock_recv, pdt, sizeof(pdt->src_addr) + sizeof(pdt->dst_addr)
                          + sizeof(pdt->src_port) + sizeof(pdt->dst_port)
                          + sizeof(pdt->seq) + sizeof(pdt->ack) + sizeof(pdt->msg_len), 0);

  if (r <= 0) {
      perror("recv");
      close(sock_recv);
      ret = 1; goto end;
  } else {
      printf("GOT %lu bytes\n", r);
  }

  msg_len = ntohs(pdt->msg_len);
  printf("msg_len: %u\n\n", msg_len);

  pdt->msg = (uint8_t*)malloc(msg_len);
  if (pdt->msg == NULL) {
    perror("malloc");
    close(sock_recv);
    ret = 2; goto end;
  }

  r = recv(sock_recv, pdt->msg, msg_len, 0);
  if (r <= 0) {
    perror("recv2");
    close(sock_recv);
    free(pdt->msg);
    ret = 1; goto end;
  }
  if (r < msg_len) {
    fprintf(stderr, "%s\n", "r = recv(sock_recv, pdt->msg, msg_len, 0) < msg_len");
    free(pdt->msg);
    ret = 2; goto end; 
  }

  if (addr_in_subnet(pdt->src_addr, inner_addr, netmask) == 0) {
    puts("FLIPPPIN!!!!!!");
    swap_pkt_data(pdt);
  }
  intercept(pdt, outer_addr, inner_addr);


  close(sock_recv);
  close(sock);

  free(pdt->msg);

end:
  free(pdt);
  free(hdt);

  return ret;
}