#ifdef VENDOR_NATIVEZYGOTE
#define LOG_TAG "nativezygote_vendor"
#else
#define LOG_TAG "nativezygote"
#endif

#include <sys/prctl.h>
#include <linux/securebits.h>
#include <android-base/file.h>
#include <log/log.h>
#include <log/log_main.h>
#include <sys/socket.h>
#include <cutils/sockets.h>
#include <string.h>
#include <android/dlext.h>
#include <stdlib.h>
#include <cutils/iosched_policy.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <selinux/android.h>
#include <sys/capability.h>
#include <dlfcn.h>

#include "nzpacket.h"
#include "util.h"

#ifdef _INIT_INIT_H
#error "Do not include init.h in files used by nativezygote; it will expose init's globals"
#endif

#ifdef VENDOR_NATIVEZYGOTE
#define SOCK_NAME "nativezygote_vendor"
#else
#define SOCK_NAME "nativezygote"
#endif

#pragma clang optimize off

using android::base::WriteStringToFile;

void set_process_cmdline(uintptr_t* data) {
  size_t argc = data[0];
  size_t total_len = 0;
  for (size_t i = 0; i < argc; ++i) {
    total_len += strlen(reinterpret_cast<const char *>(data[i+1])) + 1;
  }
  char* buf = static_cast<char *>(malloc(total_len));
  char* ptr = buf;
  for (size_t i = 0; i < argc; ++i) {
    const char *x = reinterpret_cast<const char *>(data[i+1]);
    size_t len = strlen(x);
    memcpy(ptr, x, len);
    data[i+1] = reinterpret_cast<uintptr_t>(ptr);
    ptr += len;
    *ptr = '\0';
    ++ptr;
  }
  char *end = buf + total_len + 1;
  if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, buf, 0, 0) < 0) {
    prctl(PR_SET_MM, PR_SET_MM_ARG_END, end, 0, 0);
    prctl(PR_SET_MM, PR_SET_MM_ARG_START, buf, 0, 0);
  } else {
    prctl(PR_SET_MM, PR_SET_MM_ARG_END, end, 0, 0);
  }

  const char *p, *last_slash;
  p = reinterpret_cast<const char *>(data[1]);
  last_slash = p;
  while (*p) {
    if (*p == '/') last_slash = p + 1;
    ++p;
  }
  prctl(PR_SET_NAME, last_slash, 0, 0, 0);
}

pid_t double_fork() {
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    ALOGE("Failed to pipe");
    return -1;
  }

  pid_t cpid = fork();
  if (cpid == 0) {
    // Child. Close read end.
    close(pipefd[0]);
    pid_t gcpid = fork();
    if (gcpid == 0) {
      // Grandchild. Return 0.
      close(pipefd[1]);
      return 0;
    } else {
      // Child. Report grand child PID to parent and exit.
      write(pipefd[1], &gcpid, sizeof(gcpid));
      exit(0);
    }
  } else {
    // Parent. Close write end.
    close(pipefd[1]);
    pid_t gcpid;
    read(pipefd[0], &gcpid, sizeof(gcpid));
    close(pipefd[0]);
    return gcpid;
  }
}

void set_capabilities(unsigned long long cap_set, int cap_set_size) {
  cap_t c = cap_init();
  cap_value_t value[1];
  for (int cap = 0; cap < cap_set_size; ++cap) {
    if (cap_set & (1ull << cap)) {
      // ALOGE("Setting %d %llx %llx", cap, cap_set, 1ull << cap);
      value[0] = cap;
      if (cap_set_flag(c, CAP_INHERITABLE, 1, value, CAP_SET) != 0 ||
          cap_set_flag(c, CAP_PERMITTED, 1, value, CAP_SET) != 0 ||
          cap_set_flag(c, CAP_EFFECTIVE, 1, value, CAP_SET) != 0) {
        ALOGE("Failed to set cap!");
      }
    } else {
      cap_drop_bound(cap);
    }
  }
  cap_set_proc(c);
  cap_free(c);
  for (int cap = 0; cap < cap_set_size; ++cap) {
    if (cap_set & (1ull << cap)) {
      prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0);
    }
  }
}

void preload_libraries() {
  static const char * const kLibraries[] = {
    "libbinder.so",
    "libjsoncpp.so",
    "libvndksupport.so",
    "libutils.so",
    "libprocessgroup.so",
    "liblogwrap.so",
    "libbinderthreadstate.so",
    "libhwbinder.so",
    "libminijail.so",
    "libmedia.so",
    "libstagefright.so",
    "libicuuc.so",
    "libprotobuf-cpp-lite.so",
  };

  for (int i = 0; i < sizeof(kLibraries) / sizeof(kLibraries[0]); ++i) {
    void *handle = dlopen(kLibraries[i], RTLD_LOCAL);
    if (handle) {
      ALOGE("Preloaded library %s.", kLibraries[i]);
    } else {
      ALOGE("Failed preloading library %s.", kLibraries[i]);
    }
  }
}

int main() {
#ifdef VENDOR_NATIVEZYGOTE
  ALOGE("Vendor Native Zygote starting!");
#else
  ALOGE("System Native Zygote starting!");
#endif

  preload_libraries();

  struct sigaction sa;
  sa.sa_handler = SIG_IGN; //handle signal by ignoring
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if (sigaction(SIGCHLD, &sa, 0) == -1) {
      perror(0);
      exit(1);
  }

  int ctrl_sock = android_get_control_socket(SOCK_NAME);
  if (ctrl_sock == -1) {
    ALOGE("Failed to get control socket %s!", SOCK_NAME);
    while (true);
  }
  if (listen(ctrl_sock, 1) < 0) {
    ALOGE("Failed to listen!");
    while (true);
  }
  ALOGE("Waiting for client");
  int data_sock = accept(ctrl_sock, NULL, NULL);
  ALOGE("Client connected");
  //nzpacket mypkt;
  android::init::NzPacket mypkt;
  char buf[NZPACKET_SERIALIZED_SIZE];
  while (true) {
    int bytes_read = read(data_sock, buf, sizeof(buf));
    // ALOGE("Read %d bytes!", bytes_read);
    if (!bytes_read) continue;
    int pid = double_fork();
    if (pid == 0) {
      close(data_sock);
      close(ctrl_sock);

      umask(077);

      const char *argv[128];
      if (!mypkt.Deserialize(buf)) {
          ALOGE("Failed to deserialize!");
      }

      ALOGI("Starting service: %s", mypkt.name.c_str());

      // ALOGE("%s scon = %s", mypkt.args[0].c_str(), mypkt.scon.c_str());

      argv[0] = reinterpret_cast<const char *>(mypkt.args.size());
      for (int i = 0; i < mypkt.args.size(); ++i) {
          argv[i+1] = mypkt.args[i].c_str();
      }
      argv[mypkt.args.size()+1] = nullptr;
      // set_process_cmdline(reinterpret_cast<uintptr_t*>(argv));
      for (auto desc : mypkt.descriptors) {
          // ALOGE("Descriptor: %s %s %d %d %d %s", desc->name_.c_str(), desc->type_.c_str(), desc->uid_, desc->gid_, desc->perm_, desc->context_.c_str());
          desc->CreateAndPublish(mypkt.scon);
      }
      for (const auto& file : mypkt.writepid_files) {
        if (!WriteStringToFile(std::to_string(pid), file)) {
          ALOGE("Failed to write PID to %s", file.c_str());
        }
      }
      if (mypkt.ioprio_class != IoSchedClass_NONE) {
        if (android_set_ioprio(pid, mypkt.ioprio_class, mypkt.ioprio_pri)) {
          ALOGE("Failed to set ioprio");
        }
      }

      for (const auto& rlimit : mypkt.rlimits) {
        if (setrlimit(rlimit.first, &rlimit.second) == -1) {
          ALOGE("setrlimit(%d, {rlim_cur=%ld, rlim_max=%ld}) failed",
                rlimit.first, rlimit.second.rlim_cur, rlimit.second.rlim_max);
        }
    }

      // Keep capabilities before setting uid.
      unsigned long securebits = prctl(PR_GET_SECUREBITS);
      if (securebits == -1UL) {
          ALOGE("prctl(PR_GET_SECUREBITS) failed");
      }
      securebits |= SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP;
      if (prctl(PR_SET_SECUREBITS, securebits) != 0) {
          ALOGE("prctl(PR_SET_SECUREBITS) failed");
      }

      if (setpgid(0, pid) == -1) {
        ALOGE("Failed to setpgid");
      }

      if (mypkt.gid) {
        if (setgid(mypkt.gid) != 0) {
          ALOGE("Failed to set GID");
        }
      }

      if (setgroups(mypkt.supp_gids.size(), &mypkt.supp_gids[0]) != 0) {
        ALOGE("Failed to setgroups()");
      }

      if (mypkt.uid) {
        if (setuid(mypkt.uid) != 0) {
          ALOGE("Failed to set UID");
        }
      }

      // Clear securebits we set before.
      securebits &= ~(SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP);
      if (prctl(PR_SET_SECUREBITS, securebits) != 0) {
          ALOGE("prctl(PR_SET_SECUREBITS) failed");
      }

      if (mypkt.priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, mypkt.priority) != 0) {
          ALOGE("Failed to setpriority");
        }
      }

      //g_seclabel = mypkt.seclabel;
      // if (!g_seclabel.empty()) {
      //   ALOGE("Setting exec con to %s", g_seclabel.c_str());
      //   setexeccon(g_seclabel.c_str());
      // }

      set_process_cmdline(reinterpret_cast<uintptr_t*>(argv));

      if (mypkt.has_cap_set) {
        set_capabilities(mypkt.cap_set, mypkt.cap_set_size);
      } else if (mypkt.uid) {
        set_capabilities(0ull, CAP_LAST_CAP+1);
      }

      if (setcon(mypkt.scon.c_str()) != 0) {
        ALOGE("Failed to set security context to %s", mypkt.scon.c_str());
      }

      android_load_and_run_exe(argv[1], argv);
    } else {
      write(data_sock, &pid, sizeof(pid));
    }
  }
  return 0;
}
