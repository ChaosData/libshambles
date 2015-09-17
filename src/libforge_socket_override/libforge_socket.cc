// Modified from https://github.com/ewust/forge_socket/blob/d02a284484defec31b2d99347dde4de358d82a8e/tests/libforge_socket.c
// License: (GPLv2) https://github.com/ewust/forge_socket/blob/d02a284484defec31b2d99347dde4de358d82a8e/LICENSE

#include "libforge_socket_override/libforge_socket.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>


tcp_state_t *forge_socket_new() {
    tcp_state_t *st = (tcp_state_t*)calloc(1, sizeof(tcp_state_t));
    if (st == nullptr) {
        return nullptr;
    }
    return st;
}

// Fills in all but the src/dst ip/port and seq/ack numbers
// with some sane defaults
tcp_state_t *forge_socket_get_default_state() {
    struct tcp_state *st;
    st = (tcp_state_t*)calloc(1, sizeof(tcp_state_t));
    if (st == nullptr) {
        return nullptr;
    }

    st->snd_wnd = 0x1000;
    st->rcv_wnd = 0x1000;

    return st;
}


int forge_socket_set_state(int sock, tcp_state_t *st) {
    struct sockaddr_in sin;
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = st->src_ip;
    sin.sin_port        = 0; // just need it to bind(2) to anything,
                             // then we overwrite state with intended values

    int value = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        return -1;
    }

    if (setsockopt(sock, SOL_IP, IP_TRANSPARENT, &value, sizeof(value)) < 0) {
        perror("setsockopt IP_TRANSPARENT");
        return -1;
    }

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return -1;
    }

    if (setsockopt(sock, IPPROTO_TCP, TCP_STATE, st, sizeof(tcp_state_t)) < 0) {
        perror("setsockopt TCP_STATE");
        return -1;
    }

    return 0;
}




