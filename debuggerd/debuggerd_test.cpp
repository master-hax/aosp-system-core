#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <debuggerd/protocol.h>
#include <debuggerd/util.h>
#include <gtest/gtest.h>

using android::base::unique_fd;

#if defined(__LP64__)
constexpr char kCrasherPath[] = "/system/xbin/crasher64";
#else
constexpr char kCrasherPath[] = "/system/xbin/crasher";
#endif
constexpr char kWaitForGdbKey[] = "debug.debuggerd.wait_for_gdb";

class CrasherTest : public ::testing::Test {
 public:
  pid_t crasher_pid = -1;
  bool previous_wait_for_gdb;
  unique_fd crasher_pipe;
  unique_fd intercept_fd;

  CrasherTest();
  ~CrasherTest();

  void StartIntercept(unique_fd* output_fd);

  // Returns -1 if we fail to read a response from tombstoned, otherwise the received return code.
  void FinishIntercept(int* result);

  void StartCrasher(const std::string& crash_type);
  void FinishCrasher();
  void AssertDeath(int signo);
};

CrasherTest::CrasherTest() {
  previous_wait_for_gdb = android::base::GetBoolProperty(kWaitForGdbKey, false);
  android::base::SetProperty(kWaitForGdbKey, "0");
}

CrasherTest::~CrasherTest() {
  if (crasher_pid != -1) {
    kill(crasher_pid, SIGKILL);
    int status;
    waitpid(crasher_pid, &status, WUNTRACED);
  }

  android::base::SetProperty(kWaitForGdbKey, previous_wait_for_gdb ? "1" : "0");
}

void CrasherTest::StartIntercept(unique_fd* output_fd) {
  if (crasher_pid == -1) {
    FAIL() << "crasher hasn't been started";
  }

  intercept_fd.reset(socket_local_client(kTombstonedInterceptSocketName,
                                         ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
  if (intercept_fd == -1) {
    FAIL() << "failed to contact tombstoned: " << strerror(errno);
  }

  InterceptRequest req = {.pid = crasher_pid };

  unique_fd output_pipe_write;
  if (!Pipe(output_fd, &output_pipe_write)) {
    FAIL() << "failed to create output pipe: " << strerror(errno);
  }

  // TODO: Parse /proc/sys/fs/pipe-max-size?
  constexpr size_t pipe_buffer_size = 1024 * 1024;
  if (fcntl(output_fd->get(), F_SETPIPE_SZ, pipe_buffer_size) != pipe_buffer_size) {
    FAIL() << "failed to set pipe size: " << strerror(errno);
  }

  if (send_fd(intercept_fd.get(), &req, sizeof(req), std::move(output_pipe_write)) != sizeof(req)) {
    FAIL() << "failed to send output fd to tombstoned: " << strerror(errno);
  }
}

void CrasherTest::FinishIntercept(int* result) {
  InterceptResponse response;
  ssize_t rc = TEMP_FAILURE_RETRY(read(intercept_fd.get(), &response, sizeof(response)));
  if (rc == -1) {
    FAIL() << "failed to read response from tombstoned: " << strerror(errno);
  } else if (rc == 0) {
    *result = -1;
  } else if (rc != sizeof(response)) {
    FAIL() << "received packet of unexpected length from tombstoned: expected " << sizeof(response)
           << ", received " << rc;
  }

  *result = response.success;
}

void CrasherTest::StartCrasher(const std::string& crash_type) {
  std::string type = "wait-" + crash_type;

  unique_fd crasher_read_pipe;
  if (!Pipe(&crasher_read_pipe, &crasher_pipe)) {
    FAIL() << "failed to create pipe: " << strerror(errno);
  }

  crasher_pid = fork();
  if (crasher_pid == -1) {
    FAIL() << "fork failed: " << strerror(errno);
  } else if (crasher_pid == 0) {
    unique_fd devnull(open("/dev/null", O_WRONLY));
    dup2(crasher_read_pipe.get(), STDIN_FILENO);
    dup2(devnull.get(), STDOUT_FILENO);
    dup2(devnull.get(), STDERR_FILENO);
    execl(kCrasherPath, kCrasherPath, type.c_str(), nullptr);
    err(1, "exec failed");
  }
}

void CrasherTest::FinishCrasher() {
  if (crasher_pipe == -1) {
    FAIL() << "crasher pipe uninitialized";
  }

  ssize_t rc = TEMP_FAILURE_RETRY(write(crasher_pipe.get(), "\n", 1));
  if (rc == -1) {
    printf("failed to write to crasher pipe %d: %s\n", crasher_pipe.get(), strerror(errno));
    for(;;);
    FAIL() << "failed to write to crasher pipe: " << strerror(errno);
  } else if (rc == 0) {
    FAIL() << "crasher pipe was closed";
  }
}

void CrasherTest::AssertDeath(int signo) {
  int status;
  pid_t pid = TEMP_FAILURE_RETRY(waitpid(crasher_pid, &status, 0));
  if (pid != crasher_pid) {
    FAIL() << "failed to wait for crasher: " << strerror(errno);
  }

  if (!WIFSIGNALED(status)) {
    FAIL() << "crasher didn't terminate via a signal";
  }
  ASSERT_EQ(signo, WTERMSIG(status));
  crasher_pid = -1;
}

static void ConsumeFd(unique_fd fd, std::string* output) {
  constexpr size_t read_length = PAGE_SIZE;
  std::string result;

  while (true) {
    size_t offset = result.size();
    result.resize(result.size() + PAGE_SIZE);
    ssize_t rc = TEMP_FAILURE_RETRY(read(fd.get(), &result[offset], read_length));
    if (rc == -1) {
      FAIL() << "read failed: " << strerror(errno);
    } else if (rc == 0) {
      result.resize(result.size() - PAGE_SIZE);
      break;
    }

    result.resize(result.size() - PAGE_SIZE + rc);
  }

  *output = result;
}

TEST_F(CrasherTest, smoke) {
  int intercept_result;
  unique_fd output_fd;
  StartCrasher("abort");
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  if (intercept_result != 1) {
    FAIL() << "tombstoned reported failure";
  }

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  // TODO: Check the output of the string.
}

TEST_F(CrasherTest, intercept_timeout) {
  int intercept_result;
  unique_fd output_fd;
  StartCrasher("abort");
  StartIntercept(&output_fd);
  // Don't let crasher finish until we timeout.
  FinishIntercept(&intercept_result);

  if (intercept_result == 1) {
    FAIL() << "tombstoned reported success? (intercept_result = " << intercept_result << ")";
  }

  FinishCrasher();
  AssertDeath(SIGABRT);
}

TEST_F(CrasherTest, wait_for_gdb) {
  if (!android::base::SetProperty(kWaitForGdbKey, "1")) {
    FAIL() << "failed to enable wait_for_gdb";
  }
  sleep(1);

  StartCrasher("abort");
  FinishCrasher();

  int status;
  ASSERT_EQ(crasher_pid, waitpid(crasher_pid, &status, WUNTRACED));
  ASSERT_TRUE(WIFSTOPPED(status));
  ASSERT_EQ(SIGSTOP, WSTOPSIG(status));

  ASSERT_EQ(0, kill(crasher_pid, SIGCONT));

  AssertDeath(SIGABRT);
}
