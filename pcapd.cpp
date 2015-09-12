

#define _POSIX_C_SOURCE 200112L
#undef _GNU_SOURCE
#define _BSD_SOURCE

typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;
#define EBUF_LEN 160

#include <string.h>
#include <errno.h>
#include <unistd.h>


#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>


#include "libintercept.h"


const uint8_t* strnstrn(const uint8_t* haystack, uint32_t hn, const uint8_t* needle, uint32_t nn) {
  for ( uint32_t i(0); i < hn; i++ ) {
    if ( memcmp(haystack+i, needle, nn) == 0 ) {
      return haystack+i;
    }

    if ( (i + nn) == hn) {
      break;
    }
  }
  return nullptr;
}

struct pkt_data hammer_time = {0,0, 0,0, 0,0, 0,nullptr};


void intercept(struct pkt_data* pb) {

  char ebuf[EBUF_LEN] = {0};

  int client_sock = 0;

  struct sockaddr_in remote; memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_port = htons(5555);

  int r = 0;

  r = inet_pton(AF_INET, "127.0.0.1", &remote.sin_addr);
  if (r != 1) {
    if (r == 0) {
      fprintf(stderr, "remote:inet_pton => %s\n", "Invalid network address string.");
      exit(1);
    } else {
      strerror_r(errno, ebuf, sizeof(ebuf));
      fprintf(stderr, "remote:inet_pton => %s\n", ebuf);
      exit(1);
    }
  }

  client_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (client_sock < 0) {
    strerror_r(errno, ebuf, sizeof(ebuf));
    fprintf(stderr, "client_sock:socket => %s\n", ebuf);
    exit(1);
  }

  r = connect(client_sock, (struct sockaddr*) &remote, sizeof(remote));
  if (r != 0) {
    strerror_r(errno, ebuf, sizeof(ebuf));
    fprintf(stderr, "client_sock:connect => %s\n", ebuf);
    free(hammer_time.msg);
    exit(1);
  }

  r = send(client_sock, pb, 22, 0);
  if( r < 0 ) {
    strerror_r(errno, ebuf, sizeof(ebuf));
    fprintf(stderr, "client_sock:send => %s\n", ebuf);
    exit(1);
  }

  r = send(client_sock, pb->msg, pb->msg_len, 0);
  if( r < 0 ) {
    strerror_r(errno, ebuf, sizeof(ebuf));
    fprintf(stderr, "client_sock:send => %s\n", ebuf);
    exit(1);
  }

  close(client_sock);


}


bool tcp_handler(uint32_t rsize, const uint8_t* bytes) {
  if ( rsize < sizeof(tcphdr) ) {
    return false;
  }
  puts("--->TCP!");
  tcphdr* hdr = (tcphdr*)bytes;
  uint8_t hdr_size = (hdr->th_off*4);
  if (rsize < hdr_size) {
    return false;
  }

  const uint8_t* payload = bytes + hdr_size;
  uint32_t payload_size = rsize - hdr_size;

  uint8_t query[] = "HELLO WORLD!";
  const uint8_t* match = strnstrn(payload, rsize, query, strlen((char*)query));
  if (match != nullptr) {

/* orig */

    hammer_time.src_port = hdr->th_sport;
    hammer_time.dst_port = hdr->th_dport;
    hammer_time.seq = htonl(ntohl(hdr->th_seq) + payload_size);
    hammer_time.ack = hdr->th_ack;

/* reverse attempt */
/*    hammer_time.dst_port = hdr->th_sport;
    hammer_time.src_port = hdr->th_dport;
    hammer_time.ack = hdr->th_seq;//htonl(ntohl(hdr->th_seq) + payload_size);
    hammer_time.seq = htonl(ntohl(hdr->th_ack) + payload_size);//hdr->th_ack;
*/
    hammer_time.msg_len = htons(payload_size);
    hammer_time.msg = (uint8_t*)malloc(payload_size);
    if (hammer_time.msg != nullptr) {
      memcpy(hammer_time.msg, payload, payload_size);
    }
    return true;
  }

  return false;
}

bool ip_handler(uint32_t rsize, const uint8_t* bytes) {
  if ( rsize < sizeof(ip) ) {
    return false;
  }
  puts("->IP!");

  ip* hdr4 = (ip*)bytes;
  uint8_t version = hdr4->ip_v;

  if (version == 4) {
    uint8_t ihl = hdr4->ip_hl;
    if ( rsize < ihl ) {
      return false;
    }

    uint8_t hdr4_size = ihl*4;
    const uint8_t* payload = bytes + hdr4_size;
    switch(hdr4->ip_p) {
      case IPPROTO_TCP:
         if ( tcp_handler(rsize - hdr4_size, payload) ) {
           hammer_time.src_addr = hdr4->ip_src.s_addr;
           hammer_time.dst_addr = hdr4->ip_dst.s_addr;
           return true;
         }
         return false;
        break;
      default:
        return false;
    }



  } else {
    if ( rsize < sizeof(ip6_hdr) ) {
      return false;
    }
    ip6_hdr* hdr6 = (ip6_hdr*)bytes;
    (void)hdr6;
    // not handling ipv6 right now
    return false;
  }
  return false;
}

void eth_handler(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* bytes) {
  (void)user;
  puts("GOT ONE!");
  uint32_t capturedSize = pkthdr->caplen;
  ether_header* hdr = (ether_header*)bytes;


  if (capturedSize < sizeof(ether_header)) {
    return;
  } else if (ntohs(hdr->ether_type) == ETHERTYPE_IP) {
    if ( ip_handler(capturedSize - sizeof(ether_header), bytes + sizeof(ether_header)) ) {
      puts("stop! hammer time!");
      intercept(&hammer_time);
      free(hammer_time.msg);

    }
  } else {
    puts("WAT?");
  }

  return;
}

int main() {

  pcap_t *handle;   /* Session handle */
  char dev[] = "eth2";    /* Device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
  struct bpf_program fp;    /* The compiled filter expression */
  char filter_exp[] = "port 8081";  /* The filter expression */
  bpf_u_int32 mask;   /* The netmask of our sniffing device */
  bpf_u_int32 net;    /* The IP of our sniffing device */


  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", dev);
    net = 0;
    mask = 0;
  }

  handle = pcap_open_live(dev, 1000, 0, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return(2);
  }
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }

  int loopret = pcap_loop(handle, 0, eth_handler, nullptr);
  if (loopret == -1) {
    fprintf(stderr, "Something bad happened.\n");
  } else if (loopret == -2) {
    fprintf(stderr, "Bail OUT\n");
  }





  return 0;
}
