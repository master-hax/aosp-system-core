#include <cutils/sockets.h>
#include "nzpacket.h"
#include <unistd.h>
#include <vector>
#include <string>

void constructCmdline(char *cmdline, size_t maxlength, const std::vector<std::string>& args) {
  maxlength--;
  for (auto const &arg : args) {
    const size_t length_to_copy = std::min(maxlength - 1, arg.length());
    memcpy(cmdline, arg.c_str(), length_to_copy);
    cmdline += length_to_copy;
    *cmdline = '\0';
    cmdline++;
    maxlength -= length_to_copy + 1;
  }
  *cmdline = '\0';
}

int main() {
  int sock = socket_local_client("nativezygote",
                                 ANDROID_SOCKET_NAMESPACE_RESERVED,
                                 SOCK_SEQPACKET);
  printf("Sock = %d\n", sock);
  nzpacket mypkt;
  constructCmdline(mypkt.cmdline, sizeof(mypkt.cmdline), {"/system/bin/dd", "if=/dev/zero", "of=/dev/null"});
  printf("Wrote %zd bytes\n", write(sock, &mypkt, sizeof(mypkt)));
  int pid;
  read(sock, &pid, sizeof(pid));
  printf("Child PID = %d\n", pid);
  constructCmdline(mypkt.cmdline, sizeof(mypkt.cmdline), {"/system/bin/dd", "if=/dev/random", "of=/dev/null"});
  printf("Wrote %zd bytes\n", write(sock, &mypkt, sizeof(mypkt)));
  read(sock, &pid, sizeof(pid));
  printf("Child PID = %d\n", pid);
  return 0;
}
