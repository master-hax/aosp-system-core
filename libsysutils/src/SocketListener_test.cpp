/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sysutils/FrameworkListener.h>

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <gtest/gtest.h>

#include <algorithm>

using android::base::unique_fd;
using std::string;

namespace {

string testSocketPath() {
    const testing::TestInfo* const test_info = testing::UnitTest::GetInstance()->current_test_info();
    return string(ANDROID_SOCKET_DIR "/") + string(test_info->test_case_name()) + string(".") +
           string(test_info->name());
}

unique_fd serverSocket(const string& path) {
    unlink(path.c_str());

    unique_fd fd(socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    EXPECT_GE(fd.get(), 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));

    EXPECT_EQ(bind(fd.get(), (struct sockaddr*)&addr, sizeof(addr)), 0)
        << "bind() to " << path << " failed: " << strerror(errno);
    EXPECT_EQ(android_get_control_socket(path.c_str()), -1);

    return fd;
}

unique_fd clientSocket(const string& path) {
    unique_fd fd(socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    EXPECT_GE(fd.get(), 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));

    EXPECT_EQ(0, connect(fd.get(), (struct sockaddr*)&addr, sizeof(addr)))
        << "connect() to " << path << " failed: " << strerror(errno);

    return fd;
}

void sendCmd(int fd, const char* cmd) {
    size_t len = strlen(cmd) + 1;
    EXPECT_EQ(write(fd, cmd, len), len) << "write() to socket failed: " << strerror(errno);
}

string recvReply(int fd) {
    char buf[1024];
    ssize_t len = read(fd, buf, sizeof(buf));
    EXPECT_GE(len, 0) << "read() from socket failed: " << strerror(errno);
    return len > 0 ? string(buf, buf + len) : "";
}

class TestCommand : public FrameworkCommand {
  public:
    TestCommand() : FrameworkCommand("test") {}
    ~TestCommand() override {}

    int runCommand(SocketClient* c, int argc, char** argv) {
        LOG(ERROR) << "command called: cmdNum=" << c->getCmdNum() << ", argc=" << argc
                   << ", argv[0]=" << argv[0];
        return 0;
    }
};

// A test listener with a single command.
class TestListener : public FrameworkListener {
  public:
    TestListener(int fd) : FrameworkListener(fd) {
        registerCmd(new TestCommand);  // Leaked :-(
    }
};

}  // unnamed namespace

TEST(FrameworkListener, DoesNothing) {
    const string socket_path = testSocketPath();
    unique_fd fd = serverSocket(socket_path);
    TestListener listener(fd.get());

    EXPECT_EQ(0, listener.startListener());
    EXPECT_EQ(0, listener.stopListener());

    // Wouldn't it be cool if unique_fd had a flag for doing this?
    unlink(socket_path.c_str());
}

TEST(FrameworkListener, DispatchesValidCommand) {
    const string socket_path = testSocketPath();
    unique_fd fd = serverSocket(socket_path);
    TestListener listener(fd.get());

    EXPECT_EQ(0, listener.startListener());

    unique_fd client_fd = clientSocket(socket_path);
    sendCmd(client_fd.get(), "test arg1 arg2");
    sleep(1);
    string reply = recvReply(client_fd.get());
    LOG(ERROR) << reply;

    EXPECT_EQ(0, listener.stopListener());
    unlink(socket_path.c_str());
}
