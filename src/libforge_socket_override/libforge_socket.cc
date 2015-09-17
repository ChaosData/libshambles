#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>

#include "forge_socket.h"


// TODO: one day, we should actually add a libforge_socket to the forge_socket/userspace


tcp_state_t *forge_socket_new() {
    tcp_state_t *st = (tcp_state_t*)calloc(1, sizeof(struct tcp_state));
    if (st == nullptr) {
        return nullptr;
    }
    return st;
}

uint8_t forge_socket_forge_state(int sock, struct sockaddr_in* sin, tcp_state_t *st) {
    sin->sin_family      = AF_INET;
    sin->sin_addr.s_addr = st->src_ip;
    sin->sin_port        = 0;


    int value = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        return 2;
    }

    if (setsockopt(sock, SOL_IP, IP_TRANSPARENT, &value, sizeof(value)) < 0) {
        perror("setsockopt IP_TRANSPARENT");
        return 3;
    }

    if (bind(sock, (struct sockaddr*)sin, sizeof(struct sockaddr_in)) < 0) {
        perror("bind");
        return 4;
    }

    if (setsockopt(sock, IPPROTO_TCP, TCP_STATE, st, sizeof(tcp_state_t)) < 0) {
        perror("setsockopt TCP_STATE");
        return 5;
    }

    return 0;
}


// Original-ish stuff

// Fills in all but the src/dst ip/port and seq/ack numbers
// with some sane defaults
struct tcp_state *forge_socket_get_default_state() {
    struct tcp_state *st;
    //st = malloc(sizeof(struct tcp_state));
    st = (tcp_state_t*)calloc(1, sizeof(struct tcp_state));
    if (st == nullptr) {
        return nullptr;
    }

    st->tstamp_ok = 0;
    st->sack_ok = 0;
    st->wscale_ok = 0;
    st->ecn_ok = 0;
    st->snd_wscale = 0;
    st->rcv_wscale = 0;
    st->snd_wnd = 0x1000;
    st->rcv_wnd = 0x1000;

    //make sure you set snd_una = seq (TODO: fix this in module)

    return st;
}


int forge_socket_set_state(int sock, struct tcp_state *st) {
    struct sockaddr_in sin;
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = st->src_ip;
    sin.sin_port        = 0;//st->sport;

    // TODO: maybe not everyone wants this?
    st->snd_una = st->seq;

/*
     // TOOD: do we need/want this?
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) < 0) {
        perror("setsockopt SO_BINDTODEVICE");
        return -1;
    }
*/

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

    if (setsockopt(sock, IPPROTO_TCP, TCP_STATE, st, sizeof(struct tcp_state)) < 0) {
        perror("setsockopt TCP_STATE");
        return -1;
    }

    return 0;
}




