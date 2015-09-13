#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include <unordered_map>
#include <vector>
#include <string>

#define DEFAULT_BACKLOG 128

uv_loop_t *loop;
struct sockaddr_in addr;
std::unordered_map<uv_stream_t*, std::vector<char>> streams;

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  buf->base = (char*) malloc(suggested_size);
  buf->len = suggested_size;
}

void dealloc_buffer(uv_handle_t* handle) {
  streams.erase((uv_stream_t *)handle);
  free(handle);
}

void echo_write(uv_write_t *req, int status) {
  if (status) {
    fprintf(stderr, "Write error %s\n", uv_strerror(status));
  }
  free(req);
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
  if (nread < 0) {
    if (nread != UV_EOF)
      fprintf(stderr, "Read error %s\n", uv_err_name(nread));
    uv_close((uv_handle_t*) client, dealloc_buffer);
  } else if (nread > 0) {
    std::vector<char>& v = streams[client];
    size_t size = v.size();
    printf("size: %lu, capacity: %lu\n", v.size(), v.capacity());
    //v.resize(v.capacity() + nread);
    char* current_pos = v.data() + size;
    //memset(current_pos, 0, nread);
    std::copy(buf->base, buf->base+nread, std::back_inserter(v));
    //memcpy(current_pos, buf->base, nread);

    printf("buf->base: %s\n", std::string(buf->base, nread).c_str());
    printf("data so far: %s\n===============\n", std::string(v.data(),v.size()).c_str());
    uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
    uv_buf_t wrbuf = uv_buf_init(buf->base, nread); // used b/c buf->len > nread
    uv_write(req, client, &wrbuf, 1, echo_write);
  }

  if (buf->base)
    free(buf->base);
}



void soscket_read(uv_stream_t *sock, ssize_t nread, const uv_buf_t *buf) {

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
    uv_read_start((uv_stream_t*) client, alloc_buffer, echo_read);
  }
  else {
    uv_close((uv_handle_t*) client, dealloc_buffer);
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
  uv_shutdown_t* shutdown = (uv_shutdown_t *) malloc(sizeof(uv_shutdown_t));
  if (nread < 0) {
    uv_shutdown(shutdown, server, onShutdown);
    return;
  }
  if (buf->base) {
    printf("%s\n", buf->base);
    free(buf->base);
  }
  uv_shutdown(shutdown, server, onShutdown);
}

void on_uds_connect(uv_connect_t* req, int status) {
  if (status < 0) {
    fprintf(stderr, "UDS connection error: %s\n", uv_strerror(status));
    return;
  }

  uv_read_start(req->handle, alloc_buffer, uds_read);
}

int main() {
  loop = uv_default_loop();

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
