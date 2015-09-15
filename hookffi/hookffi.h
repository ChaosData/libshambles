#ifndef LIBINTERCEPT_HOOKFFI_HOOKFFI_H_
#define LIBINTERCEPT_HOOKFFI_HOOKFFI_H_


typedef struct uds_data {
  int outer_sock;
  int inner_sock;
  int uds_client;
} uds_data_t;

typedef int hook_cb(uds_data_t* _data);

extern "C" {

int setup_server(char const * const _path);
int8_t allow_user(char const * const _path, char const * const _user);
int8_t register_hook(hook_cb* _hcb);
int8_t start(int _fd, uds_data_t* _data);
int teardown(int uds_client);

int close_forged_sockets_early(uds_data_t* _data);

}

#endif