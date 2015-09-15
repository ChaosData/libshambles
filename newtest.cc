#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <sys/capability.h>

#include <uv.h>

#include <unordered_map>
#include <vector>
#include <string>

#include <tuple>

#include "libintercept.h"
#include "util.h"

#define DEFAULT_BACKLOG 128

uv_loop_t *loop;

char const * uds_path = nullptr;
uint32_t outer_addr = 0;
uint32_t inner_addr = 0;
uint32_t netmask = 0;

std::string teardown = "teardown";

std::unordered_map<uv_stream_t*, std::vector<char>> streams;
std::unordered_map<uv_pipe_t*, pkt_data_t*> uds_state;
std::unordered_map<uv_pipe_t*, forged_sockets_t*> fst_state;

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) noexcept {
  DEBUG_printf("%s\n", __func__ );

  std::ignore = handle;
  buf->base = (char*) malloc(suggested_size);
  buf->len = suggested_size;
}

void free_socket(uv_handle_t* handle) noexcept {
  DEBUG_printf("%s\n", __func__ );

  streams.erase((uv_stream_t *)handle);
  free(handle);
}


void onUdsRead(uv_stream_t* sock, ssize_t nread, const uv_buf_t *buf) noexcept {
  DEBUG_printf("%s\n", __func__ );
  if (nread < 0) {
    if (nread != UV_EOF) {
      fprintf(stderr, "Read error %s\n", uv_err_name(nread));
      //uv_close((uv_handle_t*) sock, free_socket);
      //free(sock);
    } else {
      DEBUG_printf("%s: got EOF\n", __func__);
      uv_close((uv_handle_t*) sock, free_socket);
    }
    pkt_data_t* pdt = uds_state[(uv_pipe_t*)sock];
    uds_state.erase((uv_pipe_t*)sock);
    if(pdt->msg) {
      free(pdt->msg);
    }
    free(pdt);

  } else {
    std::vector<char>& v = streams[sock];
    std::copy(buf->base, buf->base+nread, std::back_inserter(v));
    if ( v.size() == teardown.length() ) {
      if ( std::string(v.data(), teardown.length()) == teardown) {
        DEBUG_printf("tearing down rules\n");
        pkt_data_t* pdt = uds_state[(uv_pipe_t*)sock];
        intercept_teardown(pdt, outer_addr, inner_addr);
        uds_state.erase((uv_pipe_t*)sock);
        if(pdt->msg) {
          free(pdt->msg);
        }
        free(pdt);
      }
    }
  }
  if (buf->base) {
    free(buf->base);
  }
  uv_close((uv_handle_t*) sock, free_socket);

}

void onUdsConnect(uv_connect_t* conn, int status) noexcept {
  DEBUG_printf("%s\n", __func__ );

  if (status < 0) {
    DEBUG_printf("onUdsConnect:conn->handle: %p\n", conn->handle);
    fprintf(stderr, "UDS error: %s\n", uv_strerror(status));
    forged_sockets_t* fst = fst_state[(uv_pipe_t*)conn->handle];
    fst_state.erase((uv_pipe_t*)conn->handle);
    send(fst->inner_sock, "\x00", 1, 0);  //something werid w/ the state causes
                                          //this to need data to be sent. ssems
                                          //to be due to connection tracking
                                          //not being in a position to allow in
                                          //the fin,ack from the client in
                                          //response to the server
                                          //TODO ^^^
    close(fst->outer_sock);
    close(fst->inner_sock);
    free(fst);
    
    pkt_data_t* pdt = uds_state[(uv_pipe_t*)conn->handle];
    intercept_teardown(pdt, outer_addr, inner_addr);
    if (pdt->msg) {
      free(pdt->msg);
    }
    free(pdt);
    uds_state.erase((uv_pipe_t*)conn->handle);
    uv_close((uv_handle_t*) conn->handle, free_socket);
    free(conn);
    return;
  }

  forged_sockets_t* fst = fst_state[(uv_pipe_t*)conn->handle];

  int real_uds_fd;
  int r = uv_fileno((uv_handle_t*)conn->handle, (uv_os_fd_t*)&real_uds_fd);
  if ( r == UV_EINVAL || r == UV_EBADF) {
    if (r == UV_EINVAL) {
      fprintf(stderr, "onUdsConnect:uv_fileno: passed wrong handled type\n");
    } else if (r == UV_EBADF) {
      fprintf(stderr, "onUdsConnect:uv_fileno: no file descriptor yet or "
                      "conn->handle has been closed\n");
    }
    free(conn);
    uv_close((uv_handle_t*) conn->handle, free_socket);
  }
  DEBUG_printf("sending forged packets\n");
  send_forged_sockets2(real_uds_fd, fst);
  
  //closing local handle to sockets
  close(fst->outer_sock);
  close(fst->inner_sock);
  free(fst);
  fst_state.erase((uv_pipe_t*)conn->handle);

  uv_read_start((uv_stream_t*) conn->handle, alloc_buffer, onUdsRead);
  free(conn);
}


int8_t onPktDataReceived(uv_stream_t* sock, pkt_data_t* pdt) noexcept {
  DEBUG_printf("%s\n", __func__ );

  std::ignore = sock;


  if (addr_in_subnet(pdt->src_addr, inner_addr, netmask) == 0) {
    swap_pkt_data_inline(pdt);
  }
  forged_sockets_t* fst = (forged_sockets_t*)malloc(sizeof(forged_sockets_t));

  if (intercept(fst, pdt, outer_addr, inner_addr) != 1) {
    fprintf(stderr, "Can't setup intercept\n");
    free(fst);
    uv_close((uv_handle_t*) sock, free_socket);
    return -1;
  }

  uv_pipe_t* uds_handle = (uv_pipe_t*)malloc(sizeof(uv_pipe_t));
  if (uds_handle == nullptr) {
    fprintf(stderr, "onPktDataReceived:(uv_pipe_t*)malloc: null\n");
    free(uds_handle);
    free(fst);
    return -2;
  }
  uv_pipe_init(loop, uds_handle, 0);

  uds_state[uds_handle] = pdt;
  fst_state[uds_handle] = fst;

  uv_connect_t* conn = (uv_connect_t*)malloc(sizeof(uv_connect_t));
  DEBUG_printf("onPktDataReceived:uds_handle: %p\n", uds_handle);


  uv_pipe_connect(conn, uds_handle, uds_path, onUdsConnect);

  return 0;
}

void onRead(uv_stream_t* sock, ssize_t nread, const uv_buf_t *buf) noexcept {
  DEBUG_printf("%s\n", __func__ );

  if (nread < 0) {
    if (nread != UV_EOF) {
      fprintf(stderr, "Read error %s\n", uv_err_name(nread));
      uv_close((uv_handle_t*) sock, free_socket);
    } else {
      DEBUG_printf("%s: got EOF\n", __func__);
      uv_close((uv_handle_t*) sock, free_socket);
    }
  } else if (nread > 0) {
    DEBUG_printf("%s: %ld bytes read\n", __func__, nread);
    std::vector<char>& v = streams[sock];
    std::copy(buf->base, buf->base+nread, std::back_inserter(v));

    if (v.size() >= sizeof(pkt_data_t)-sizeof(uint8_t*)) {
      uint16_t msg_len = reinterpret_cast<pkt_data_t*>(v.data())->msg_len;
      if (v.size() >= sizeof(pkt_data_t)-sizeof(uint8_t*)+msg_len) {
        pkt_data_t* pdt = (pkt_data_t*)malloc(sizeof(pkt_data_t));
        if ( pdt == nullptr ) {
          uv_close((uv_handle_t*) sock, free_socket);
          return;
        }
        memcpy(pdt, v.data(), sizeof(pkt_data_t)-sizeof(uint8_t*));
        pdt->msg = (uint8_t*)malloc(msg_len);
        memcpy(pdt->msg,
               v.data()+sizeof(pkt_data_t)-sizeof(uint8_t*),
               msg_len
        );
        int8_t r = onPktDataReceived(sock, pdt);
        if (r != 0) {
          if ( r == -2 ) {
            intercept_teardown(pdt, outer_addr, inner_addr);
          }

          if (pdt->msg) {
            free(pdt->msg);
          }
          free(pdt);
          if (buf->base) {
            free(buf->base);
          }
          return;
        }

        if (v.size() > sizeof(pkt_data_t)-sizeof(uint8_t*)+msg_len) {
          v = std::vector<char>(
            v.begin()+sizeof(pkt_data_t)-sizeof(uint8_t*)+msg_len,
            v.end()
          );
        }
      }
    }
  } else {
    DEBUG_printf("%s: no bytes read\n", __func__);
  }

  if (buf->base) {
    free(buf->base);
  }
}


void on_new_connection(uv_stream_t *server, int status) noexcept {
  DEBUG_printf("%s\n", __func__ );

  if (status < 0) {
    fprintf(stderr, "New connection error: %s\n", uv_strerror(status));
    // error!
    return;
  }
  DEBUG_printf("new connection: %p\n", server);

  uv_tcp_t *client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
  //blocks will be "possibly lost" in valgrind when ^C-ing b/c we keep the
  //connection alive

  uv_tcp_init(loop, client);
  if (uv_accept(server, (uv_stream_t*) client) == 0) {
    uv_read_start((uv_stream_t*) client, alloc_buffer, onRead);
  }
  else {
    uv_close((uv_handle_t*) client, free_socket);
  }
}

void cleanup(int sig) noexcept {
  DEBUG_printf("%s\n", __func__ );

  (void)sig;
  uv_loop_close(loop);
  free(loop);
  exit(0);
}

void onShutdown(uv_shutdown_t* req, int status) noexcept {
  DEBUG_printf("%s\n", __func__ );

  (void)status;
  free(req);
}

int main(int argc, char const *argv[]) noexcept {
  if (argc != 5) {
    fprintf(stderr, "Usage: ./%s <public IP> <internal IP> <internal netmask> "
                    "<unix domain socket path>\n", argv[0]);
    return -1;
  }

  if ( parse_ipv4(argv[1], strlen(argv[1])) != 0 ) {
    fprintf(stderr, "Invalid <public IP> value: %s\n", argv[1]);
    return -2;
  }

  if ( parse_ipv4(argv[2], strlen(argv[2])) != 0 ) {
    fprintf(stderr, "Invalid <internal IP> value: %s\n", argv[2]);
    return -3;
  }

  if ( parse_ipv4(argv[3], strlen(argv[3])) != 0 ) {
    fprintf(stderr, "Invalid <internal netmask> value: %s\n", argv[3]);
    return -4;
  }


  DEBUG_printf("Validating privileges.\n");
  cap_value_t required_capability_list[2] = { CAP_NET_ADMIN, CAP_NET_RAW };
  cap_t capabilities;


  capabilities = cap_get_proc();
  if (capabilities == NULL) {
    fprintf(stderr, "Can't get capabilities information, exiting.\n");
    return -5;
  }
 
  cap_value_t cap = CAP_NET_ADMIN;
  cap_flag_value_t has_cap;
  if(cap_get_flag(capabilities, cap, CAP_PERMITTED, &has_cap) != 0) {
    fprintf(stderr, "Invalid capability check? Exiting.\n");
    return -6;
  }
  if (!has_cap) {
    fprintf(stderr, "Process does not have CAP_NET_ADMIN, exiting.\n");
    return -7;
  }

  cap = CAP_NET_RAW; 
  if(cap_get_flag(capabilities, cap, CAP_PERMITTED, &has_cap) != 0) {
    fprintf(stderr, "Invalid capability check?\n");
    return -8;
  }
  if (!has_cap) {
    fprintf(stderr, "Process does not have CAP_NET_RAW, exiting.\n");
    return -9;
  }


  DEBUG_printf("Dropping privileges.\n");
  if (cap_clear(capabilities) == -1) {
    fprintf(stderr, "Can't clear capabilities, exiting.\n");
    return -10;
  }



  if (cap_set_flag(capabilities, CAP_PERMITTED,
        sizeof(required_capability_list)/sizeof(required_capability_list[0]),
        required_capability_list, CAP_SET) == -1) {
    fprintf(stderr, "Error setting capabilities flags, exiting.\n");
    return -11;
  }

  if (cap_set_flag(capabilities, CAP_EFFECTIVE,//CAP_PERMITTED,
        sizeof(required_capability_list)/sizeof(required_capability_list[0]),
        required_capability_list, CAP_SET) == -1) {
    fprintf(stderr, "Error setting capabilities flags, exiting.\n");
    return -11;
  }
  

  if (cap_set_proc(capabilities) == -1) {
    fprintf(stderr, "Can't set restricted capabilities subset, exiting.\n");
    return -11;
  } 


  if ( cap_free(capabilities) == -1 ) {
    fprintf(stderr, "Could not free capabilities structures, exiting.\n");
    return -12;
  }

  outer_addr = inet_addr(argv[1]);
  inner_addr = inet_addr(argv[2]);
  netmask = inet_addr(argv[3]);
  uds_path = argv[4];

  loop = (uv_loop_t*)malloc(sizeof(uv_loop_t));
  uv_loop_init(loop);

//  loop = uv_default_loop();
  struct sockaddr_in addr;

  uv_tcp_t tcp_server;
  uv_tcp_init(loop, &tcp_server);

  uv_ip4_addr("127.0.0.1", 5555, &addr);

  uv_tcp_bind(&tcp_server, (const struct sockaddr*)&addr, 0);
  int r = uv_listen((uv_stream_t*) &tcp_server,
                    DEFAULT_BACKLOG,
                    on_new_connection
  );
  if (r == -1) {
    fprintf(stderr, "Listen error %s\n", uv_strerror(r));
    return -13;
  }

  signal(SIGINT, cleanup);
  return uv_run(loop, UV_RUN_DEFAULT);
}
