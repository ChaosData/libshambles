#include <stdlib.h>
#include <stdio.h>


#include <stdint.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>


int main(int argc, char const * const argv[]) {
  char const * const path = argv[1];

  struct sockaddr_un addr;
  int fd;

  if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
    perror("main:socket");
    return fd;
  }

  memset(&addr, 0, sizeof(addr));

  addr.sun_family = AF_LOCAL;
  unlink(path);
  strcpy(addr.sun_path, path);

  if (bind(fd, (struct sockaddr *) &(addr),
                              sizeof(addr)) < 0) {
    perror("main:bind");
    return -1;
  }

  if (listen(fd, 1) < 0) {
    perror("main:listen");
    return -1;
  }

  struct sockaddr_un remote;
  int len = sizeof(struct sockaddr_un);
  int peer = accept(fd, (struct sockaddr*)&remote, (socklen_t *)&len);




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

  struct msghdr msgh;
   struct cmsghdr *cmsg;
   int *ttlptr;
   int received_ttl;

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
   return res;
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

  int r = 0;
  char rec[1024] = {0};

  puts("recv'ing from client:");
  r = recv(sent_fd[0], rec, sizeof(rec), 0);
  printf("GOT (outer): %s\n", rec);

  memset(rec, 0, sizeof(rec));

  puts("recv'ing from client:");
  r = recv(sent_fd[1], rec, sizeof(rec), 0);
  printf("GOT (inner): %s\n", rec);

  close(sent_fd[0]);
  close(sent_fd[1]);


  return 0;
}