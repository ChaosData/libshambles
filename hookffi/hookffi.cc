#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include <stdint.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

#include <string>
#include <regex>
#include <cctype>

#include "hookffi.h"

std::string const linux_username_regex_str = "^[a-z_][a-z0-9_-]*[$]?$";
std::regex const linux_username_regex(linux_username_regex_str);

constexpr static char TEARDOWN_CMD[] = "teardown";
constexpr static size_t TEARDOWN_CMD_LEN  = sizeof(TEARDOWN_CMD)-1;


hook_cb * callback = nullptr;





int setup_server(char const * const _path) {
  DEBUG_printf("%s\n", __func__);

  struct sockaddr_un addr;
  int fd;

  if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
    perror("main:socket");
    return -3;
  }

  memset(&addr, 0, sizeof(addr));

  addr.sun_family = AF_LOCAL;
  strcpy(addr.sun_path, _path);

  unlink(_path);
  if (bind(fd, (struct sockaddr *) &(addr),
                              sizeof(addr)) < 0) {
    perror("main:bind");
    return -4;
  }

  if (listen(fd, 1) < 0) {
    perror("main:listen");
    return -5;
  }

  return fd;
}


bool is_numeric(const std::string& s) {
    return !s.empty() && std::find_if(
        s.begin(), 
        s.end(),
        [](char c) {
          return !std::isdigit(c);
        }) == s.end();
}

int8_t allow_user(char const * const _path, char const * const _user) {
  DEBUG_printf("%s\n", __func__);
  std::string uname = _user;

  if (!is_numeric(uname) && !std::regex_match(uname, linux_username_regex)) {
    return -1;
  }

  pid_t pid = fork();
  if(pid >= 0) {
    if(pid == 0) { //child
      std::string acl = "u:" + uname + ":rwx";
      const char* const execve_argv[] = {"setfacl", "-m", acl.c_str(), _path, nullptr};

      execve("/bin/setfacl", const_cast<char *const *>(execve_argv), nullptr);
    }
  }
  else {
    perror("fork");
    return -2;
  }
  return 0;
}

int8_t register_hook(hook_cb* _hcb) {
  DEBUG_printf("%s\n", __func__);

  callback = _hcb;
  return 0;
}


void cleanup(int sig) noexcept {
  DEBUG_printf("%s\n", __func__);

  (void)sig;
  exit(0);
}

int8_t start(int _fd, uds_data_t* _data) {
  DEBUG_printf("%s: _fd:%d, _data:%p\n", __func__, _fd, _data);

  signal(SIGINT, cleanup);

  struct sockaddr_un remote;
  int len = sizeof(struct sockaddr_un);
  int pid = 0;
  while (true) {

    int peer = accept(_fd, (struct sockaddr*)&remote, (socklen_t *)&len);
    DEBUG_printf("peer: %d\n", peer);
    
    pid = fork();
    if (pid == -1) {
      close(peer);
      continue;
    } else if (pid > 0) {
      close(peer);
      continue;
    }
    

    int sent_fd[2];
    struct msghdr message;
    struct iovec iov[1];
    struct cmsghdr *control_message = NULL;
    union {
      /* ancillary data buffer, wrapped in a union in order to ensure
      it is suitably aligned */
      char buf[CMSG_SPACE(sizeof(sent_fd))];
      struct cmsghdr align;
    } u;

    char data[1];
    int res;

    memset(&message, 0, sizeof(struct msghdr));

    /* For the dummy data */
    iov[0].iov_base = data;
    iov[0].iov_len = sizeof(data);

    message.msg_name = NULL;
    message.msg_namelen = 0;
    message.msg_control = u.buf;
    message.msg_controllen = sizeof(u.buf);
    message.msg_iov = iov;
    message.msg_iovlen = 1;

    if((res = recvmsg(peer, &message, 0)) <= 0) {
      perror("recvmsg");
      return -1;
    }

    /* Iterate through header to find if there is a file descriptor */
    for(control_message = CMSG_FIRSTHDR(&message);
        control_message != NULL;
        control_message = CMSG_NXTHDR(&message,
                                      control_message)) {
      if( (control_message->cmsg_level == SOL_SOCKET) &&
          (control_message->cmsg_type == SCM_RIGHTS) ) {
        memcpy(sent_fd, CMSG_DATA(control_message), sizeof(int)*2);
      }
    }

    _data->outer_sock = sent_fd[0];
    _data->inner_sock = sent_fd[1];
    _data->uds_client = peer;
    (*callback)(_data);
  }
  return 1;
}

int teardown(uds_data_t* _data) {
  DEBUG_printf("%s\n", __func__);
  close(_data->outer_sock);
  close(_data->inner_sock);

  send(_data->uds_client, TEARDOWN_CMD, TEARDOWN_CMD_LEN, 0);
  return close(_data->uds_client);
}


int close_forged_sockets_early(uds_data_t* _data) {
  DEBUG_printf("%s\n", __func__);

  //used b/c of conntrack/snat/dnat quirk
  send(_data->inner_sock, "\x00", 1, 0);
  
  close(_data->outer_sock);
  close(_data->inner_sock);
  return 0;
}

