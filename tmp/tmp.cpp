#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>

static sockaddr_in addr;

int listen_socket(void) {
  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (fd == -1) {
    err(1, "failed to create socket");
  }

  int opt = 1;
  if (setsockopt(3, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
    err(1, "failed to setsockopt");
  }

  if (bind(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
    err(1, "failed to bind");
  }

  if (listen(fd, 0) != 0) {
    err(1, "failed to listen");
  }

  return fd;
}

int main() {
  addr.sin_family = AF_INET;
  addr.sin_port = htons(12345);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  int server = listen_socket();
  int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_IP);
  if (client == -1) {
    err(1, "failed to create client socket");
  }

  int rc = connect(client, (sockaddr*)&addr, sizeof(addr));
  if (rc != -1) {
    errx(1, "connect immediately succeeded");
  } else if (errno != EINPROGRESS) {
    err(1, "connect failed");
  }

  struct pollfd pfd = {
    .fd = client,
    .events = POLLOUT,
  };

  rc = poll(&pfd, 1, 1000);
  if (rc == -1) {
    err(1, "poll failed");
  } else if (rc == 1) {
    printf("connect finished\n");
  } else {
    printf("connect still blocking after 1s\n");
  }
}
