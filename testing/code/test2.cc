#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include <unordered_map>
#include <vector>
#include <string>

#include "../../libintercept.h"
#include "../../util.h"

#define DEFAULT_BACKLOG 128


uv_loop_t *loop;

char* uds_path = nullptr;
uint32_t outer_addr = 0;
uint32_t inner_addr = 0;
uint32_t netmask = 0;

std::string teardown = "teardown";

std::unordered_map<uv_stream_t*, std::vector<char>> streams;
std::unordered_map<uv_pipe_t*, pkt_data_t*> uds_state;

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  (void)handle;
  buf->base = (char*) malloc(suggested_size);
  buf->len = suggested_size;
}

void free_socket(uv_handle_t* handle) {
  streams.erase((uv_stream_t *)handle);
  free(handle);
}

void echo_write(uv_write_t *req, int status) {
  if (status) {
    fprintf(stderr, "Write error %s\n", uv_strerror(status));
  }
  free(req);
}


void onUdsRead(uv_stream_t* sock, ssize_t nread, const uv_buf_t *buf) {
    std::vector<char>& v = streams[sock];
    std::copy(buf->base, buf->base+nread, std::back_inserter(v));
    if ( v.size() == teardown.length() ) {
      if ( std::string(v.data(), teardown.length()) == teardown) {
        pkt_data_t* pdt = uds_state[(uv_pipe_t*)sock];
        //intercept_teardown(pdt, outer_addr, inner_addr);
        uds_state.erase((uv_pipe_t*)sock);
        uv_close((uv_handle_t*) sock, free_socket);
      }
    }
}

void onUdsConnect(uv_connect_t* conn, int status) {
  if (status < 0) {
    fprintf(stderr, "UDS error: %s\n", uv_strerror(status));
    return;
  }

  pkt_data_t* pdt = uds_state[(uv_pipe_t*) conn->handle];

  //if (addr_in_subnet(pdt->src_addr, inner_addr, netmask) == 0) {
  //  swap_pkt_data_inline(pdt);
  //}
  //forged_sockets_t fst;
  //intercept(&fst, pdt, outer_addr, inner_addr);

  int real_uds_fd;
  int r = uv_fileno((uv_handle_t*)conn->handle, (uv_os_fd_t*)&real_uds_fd);
  if ( r == UV_EINVAL || r == UV_EBADF) {
    if (r == UV_EINVAL) {
      fprintf(stderr, "onUdsConnect:uv_fileno: passed wrong handled type\n");
    } else if (r == UV_EBADF) {
      fprintf(stderr, "onUdsConnect:uv_fileno: no file descriptor yet or "
                      "conn->handle has been closed\n");
    }
    uv_close((uv_handle_t*) conn->handle, free_socket);
  }

  //send_forged_sockets2(real_uds_fd, &fst, uds_path);




  //uv_read_start(req->handle, alloc_buffer, NULL);
}


void onPktDataReceived(uv_stream_t* sock, pkt_data_t* pdt) {
  //calloc a pkt_data_t
  //put pkt_data_t in an unordered_map<uv_pipe_t*, pkt_data_t*>
  //do uds connect (on success, do intercepts and send forgedsockets [using raw fd] via callback)
  //set up an onUdsRead for it that will wait for a teardown command


  uv_pipe_t* uds_handle = (uv_pipe_t*)malloc(sizeof(uv_pipe_t));
  uv_pipe_init(loop, uds_handle, 0);

  uds_state[uds_handle] = pdt;

  uv_connect_t conn;
  uv_pipe_connect(&conn, uds_handle, uds_path, onUdsConnect);


}

void onRead(uv_stream_t* sock, ssize_t nread, const uv_buf_t *buf) {
  if (nread < 0) {
    if (nread != UV_EOF)
      fprintf(stderr, "Read error %s\n", uv_err_name(nread));
      uv_close((uv_handle_t*) sock, free_socket);
  } else if (nread > 0) {
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

        onPktDataReceived(sock, pdt);

        if (v.size() > sizeof(pkt_data_t)-sizeof(uint8_t*)+msg_len) {
          v = std::vector<char>(
            v.begin()+sizeof(pkt_data_t)-sizeof(uint8_t*)+msg_len,
            v.end()
          );
        }
      }
    }
  }

  if (buf->base) {
    free(buf->base);
  }
}


void on_new_connection(uv_stream_t *server, int status) {
  if (status < 0) {
    fprintf(stderr, "New connection error %s\n", uv_strerror(status));
    // error!
    return;
  }

  uv_tcp_t *client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
  uv_tcp_init(loop, client);
  if (uv_accept(server, (uv_stream_t*) client) == 0) {
    uv_read_start((uv_stream_t*) client, alloc_buffer, onRead);
  }
  else {
    uv_close((uv_handle_t*) client, free_socket);
  }
}

void cleanup(int sig) {
  (void)sig;
//  uv_fs_t req;
//  uv_fs_unlink(loop, &req, "/tmp/echo.sock", NULL);
  uv_loop_close(loop);
  exit(0);
}

void onShutdown(uv_shutdown_t* req, int status) {
  (void)status;
  free(req);
}

void uds_read(uv_stream_t *server, ssize_t nread, const uv_buf_t *buf) {
  printf("uds_read:server: %p\n", server);

  uv_shutdown_t* shutdown = (uv_shutdown_t *) malloc(sizeof(uv_shutdown_t));
  if (nread < 0) {
    uv_shutdown(shutdown, server, onShutdown);
    return;
  }
  if (buf->base) {
    printf("%s\n", std::string(buf->base, nread).c_str());
    free(buf->base);
  }
  uv_shutdown(shutdown, server, onShutdown);
}

void on_uds_connect(uv_connect_t* req, int status) {
  printf("on_uds_connect:req: %p\n", req);
  printf("on_uds_connect:req->handle: %p\n", req->handle);

  if (status < 0) {
    fprintf(stderr, "UDS connection error: %s\n", uv_strerror(status));
    return;
  }

  uv_read_start(req->handle, alloc_buffer, uds_read);
}

int main(int argc, char const *argv[]) {
  if (argc != 5) {
    fputs("Usage: ./shambles <public IP> <internal IP> <internal netmask> "
          "<unix domain socket path>\n", stderr);
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


  loop = uv_default_loop();
  struct sockaddr_in addr;

  uv_tcp_t tcp_server;
  uv_tcp_init(loop, &tcp_server);

  uv_ip4_addr("127.0.0.1", 5555, &addr);

  uv_tcp_bind(&tcp_server, (const struct sockaddr*)&addr, 0);
  int r = uv_listen((uv_stream_t*) &tcp_server,
                    DEFAULT_BACKLOG,
                    on_new_connection
  );
  if (r) {
    fprintf(stderr, "Listen error %s\n", uv_strerror(r));
    return 1;
  }

  uv_pipe_t uds_handle;
  printf("&uds_handle: %p\n", &uds_handle);
  puts("WAT?");
  uv_pipe_init(loop, &uds_handle, 0);


/*  if ((r = uv_pipe_bind(&uds_server, "/tmp/echo.sock"))) {
    fprintf(stderr, "Bind error %s\n", uv_err_name(r));
    return 1;
  }
  if ((r = uv_listen((uv_stream_t*) &uds_server, 128, on_new_connection))) {
    fprintf(stderr, "Listen error %s\n", uv_err_name(r));
    return 2;
  }
*/
  uv_connect_t conn;
  uv_pipe_connect(&conn, &uds_handle, "/tmp/echo.sock", on_uds_connect);

  signal(SIGINT, cleanup);
  return uv_run(loop, UV_RUN_DEFAULT);



}
