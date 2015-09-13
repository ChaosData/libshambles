#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include <unordered_map>
#include <vector>
#include <string>

#define DEFAULT_BACKLOG 128


typedef struct __attribute__((__packed__)) pkt_data {
  uint32_t src_addr;
  uint32_t dst_addr;

  uint16_t src_port;
  uint16_t dst_port;

  uint32_t seq;
  uint32_t ack;

  uint16_t msg_len;
  uint8_t* msg;
} pkt_data_t;


uv_loop_t *loop;

char* uds_path = nullptr;
uint32_t outer_addr = 0;
uint32_t inner_addr = 0;
uint32_t netmask = 0;

std::unordered_map<uv_stream_t*, std::vector<char>> streams;
std::unordered_map<uv_pipe_t*, pkt_data_t*> uds_state;

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
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




void onUdsConnect(uv_connect_t* conn, int status) {
  if (status < 0) {
    fprintf(stderr, "UDS error: %s\n", uv_strerror(status));
    return;
  }

  pkt_data_t* pdt = uds_state[(uv_pipe_t*) conn->handle];




  //uv_read_start(req->handle, alloc_buffer, NULL);
}

void onPktDataReceived(uv_stream_t* sock, char* data) {
  //calloc a pkt_data_t
  //put pkt_data_t in an unordered_map<uv_pipe_t*, pkt_data_t*>
  //do uds connect (on success, do intercepts and send forgedsockets [using raw fd] via callback)
  //set up an onUdsRead for it that will wait for a teardown command
  pkt_data_t* pdt = (pkt_data_t*)calloc(1, sizeof(pkt_data_t));
  if ( pdt == nullptr ) {
    return;
  }
  memcpy(pdt, data, sizeof(pkt_data_t));

  uv_pipe_t* uds_handle = (uv_pipe_t*)malloc(sizeof(uv_pipe_t));
  uv_pipe_init(loop, uds_handle, 0);

  uds_state[uds_handle] = pdt;

  uv_connect_t conn;
  uv_pipe_connect(&conn, uds_handle, uds_path, onUdsConnect);


}

void onReadPktDataHeader(uv_stream_t* sock, ssize_t nread, const uv_buf_t *buf) {
  if (nread < 0) {
    if (nread != UV_EOF)
      fprintf(stderr, "Read error %s\n", uv_err_name(nread));
      uv_close((uv_handle_t*) sock, free_socket);
  } else if (nread > 0) {
    if (nread >= sizeof(pkt_data_t)) {
      onPktDataReceived(sock, buf->base);
//      uv_close((uv_handle_t*) sock, free_socket);
    } else {
      std::vector<char>& v = streams[sock];
      size_t size = v.size();
      char* current_pos = v.data() + size;
      std::copy(buf->base, buf->base+nread, std::back_inserter(v));
      if (v.size() == sizeof(pkt_data_t)) {
        onPktDataReceived(sock, v.data());
//        uv_close((uv_handle_t*) sock, free_socket);
      } else if (v.size() > sizeof(pkt_data_t)) {
//        uv_close((uv_handle_t*) sock, free_socket);
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
    uv_read_start((uv_stream_t*) client, alloc_buffer, onReadPktDataHeader);
  }
  else {
    uv_close((uv_handle_t*) client, free_socket);
  }
}

void cleanup(int sig) {
//  uv_fs_t req;
//  uv_fs_unlink(loop, &req, "/tmp/echo.sock", NULL);
  uv_loop_close(loop);
  exit(0);
}

void onShutdown(uv_shutdown_t* req, int status) {
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

int main() {
  loop = uv_default_loop();
  struct sockaddr_in addr;

  uv_tcp_t tcp_server;
  uv_tcp_init(loop, &tcp_server);

  uv_ip4_addr("127.0.0.1", 5555, &addr);

  uv_tcp_bind(&tcp_server, (const struct sockaddr*)&addr, 0);
  int r = uv_listen((uv_stream_t*) &tcp_server, DEFAULT_BACKLOG, on_new_connection);
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
