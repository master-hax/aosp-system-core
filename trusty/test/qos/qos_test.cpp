/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <android-base/result.h>
#include <android-base/unique_fd.h>
// #include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <trusty/busy_test/busy_test_client.h>
#include <trusty/tipc.h>
#include <sstream>

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;

/* trusty thread priorities */
#define NUM_PRIORITIES 32
#define LOWEST_PRIORITY 0
#define HIGHEST_PRIORITY (NUM_PRIORITIES - 1)
#define DPC_PRIORITY (NUM_PRIORITIES - 2)
#define IDLE_PRIORITY LOWEST_PRIORITY
#define LOW_PRIORITY (NUM_PRIORITIES / 4)
#define DEFAULT_PRIORITY (NUM_PRIORITIES / 2)
#define HIGH_PRIORITY ((NUM_PRIORITIES / 4) * 3)

#define LINUX_NICE_FOR_TRUSTY_PRIORITY_LOW 10
#define LINUX_NICE_FOR_TRUSTY_PRIORITY_NORMAL 0
#define LINUX_NICE_FOR_TRUSTY_PRIORITY_HIGH -20

/** DOC:
 * ./build-root/build-qemu-generic-arm64-test-debug/run \
 *       --android $HOME/depot/android/aosp \
 *       --headless --shell-command "/data/nativetest64/vendor/trusty-qos-test/trusty-qos-test"
 */
constexpr const char kTrustyDefaultDeviceName[] = "/dev/trusty-ipc-dev0";
constexpr const char kTrustyBusyPortTest[] = "com.android.kernel.busy-test";

// trim from start (in place)
static inline void ltrim(std::string& s) {
    s.erase(s.begin(),
            std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
}

// trim from end (in place)
static inline void rtrim(std::string& s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); })
                    .base(),
            s.end());
}

// trim from end (in place)
static inline void crtrim(std::string& s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return ch != '\n'; }).base(),
            s.end());
}

// trim from both ends (in place)
static inline void trim(std::string& s) {
    rtrim(s);
    ltrim(s);
    crtrim(s);
}

inline int CStringToInt32(const char* s, int32_t* value, int base = 10) {
    char* endptr = nullptr;
    auto value_maybe = static_cast<int32_t>(strtol(s, &endptr, base));
    if (*s && !*endptr) {
        *value = value_maybe;
        return 0;
    }
    return -1;
}

inline int CStringToUInt32(const char* s, uint32_t* value, int base = 10) {
    char* endptr = nullptr;
    auto value_maybe = static_cast<uint32_t>(strtoul(s, &endptr, base));
    if (*s && !*endptr) {
        *value = value_maybe;
        return 0;
    }
    return -1;
}

static int RunSystemCmd(const std::string& cmd, char* buf, size_t len, int line_num = 1) {
    FILE* cmd_pipe = popen(cmd.c_str(), "r");  // NOLINT(cert-env33-c): test code
    if (cmd_pipe == nullptr) {
        ALOGE("Cannot open pipe for %s", cmd.c_str());
        return -1;
    }
    for (int i = 0; i < line_num; i++) {
        if (fgets(buf, len, cmd_pipe) == nullptr) {
            ALOGE("Cannot read pipe for %s", cmd.c_str());
            pclose(cmd_pipe);
            return -1;
        }
    }
    pclose(cmd_pipe);
    ALOGD("%s", cmd.c_str());
    ALOGD("%s", buf);
    return 0;
}

static int GetTrustyWorkerNice(uint32_t cpu, int32_t* nice) {
    char buf[1024];
    std::string cmd = std::string("pgrep trusty-nop-") + std::to_string(cpu);
    auto rc = RunSystemCmd(cmd, buf, sizeof(buf));
    if (rc != 0) {
        return rc;
    }
    cmd = std::string("ps -e -o ni ") + std::string(buf);
    rc = RunSystemCmd(cmd, buf, sizeof(buf), 2);
    if (rc != 0) {
        return rc;
    }
    std::string res(buf);
    trim(res);
    rc = CStringToInt32(res.c_str(), nice);
    if (rc != 0) {
        ALOGE("Cannot convert %s to Int32", res.c_str());
        return rc;
    }
    return 0;
}

static int GetCpuNb(uint32_t* cpuNb) {
    char buf[1024];
    std::string cmd = std::string("nproc --all");
    auto rc = RunSystemCmd(cmd, buf, sizeof(buf));
    if (rc != 0) {
        return rc;
    }
    std::string res(buf);
    trim(res);
    rc = CStringToUInt32(res.c_str(), cpuNb);
    if (rc != 0) {
        ALOGE("Cannot convert %s to Int32", res.c_str());
        return rc;
    }
    return 0;
}

static uint32_t GetNice(uint32_t priority) {
    if (priority >= HIGH_PRIORITY) {
        return LINUX_NICE_FOR_TRUSTY_PRIORITY_HIGH;
    } else if (priority <= LOW_PRIORITY) {
        return LINUX_NICE_FOR_TRUSTY_PRIORITY_LOW;
    }
    return LINUX_NICE_FOR_TRUSTY_PRIORITY_NORMAL;
}

namespace android {
namespace trusty {
namespace qos {
class TrustyQosEnv : public ::testing::Environment {
  public:
    TrustyQosEnv() : mPortTestFd(-1) {}

    void SetUp() override {
        OpenBusyTest();
        auto rc = GetCpuNb(&mMaxCpus);
        ASSERT_TRUE(rc == 0);
    }
    void TearDown() override {
        // note: mPortTestFd unique_fd will close on TrustyQosTest dtor
    }
    void SetPriority(uint32_t cpu, uint32_t priority) {
        auto rc = busy_test_set_priority(mPortTestFd, cpu, priority);
        ASSERT_EQ(rc, BUSY_TEST_NO_ERROR);
    }
    uint32_t MaxCpus() { return mMaxCpus; }

  private:
    void OpenBusyTest() {
        int fd = tipc_connect(kTrustyDefaultDeviceName, kTrustyBusyPortTest);
        ASSERT_FALSE(fd < 0);
        mPortTestFd.reset(fd);
    }
    unique_fd mPortTestFd;
    uint32_t mMaxCpus;
};
TrustyQosEnv* qosEnv = nullptr;

class TrustyQosTest : public ::testing::TestWithParam<std::tuple<uint32_t, uint32_t>> {
  protected:
    TrustyQosTest() {}
    void SetUp() override { ASSERT_TRUE(qosEnv); }
    void TearDown() override {}
};

TEST_P(TrustyQosTest, SetPriority) {
    auto param = GetParam();
    uint32_t cpu = std::get<0>(param);
    uint32_t priority = std::get<1>(param);
    int32_t nice;
    int32_t nice_low = GetNice(LOW_PRIORITY);
    int32_t nice_expected = GetNice(priority);
    if (cpu >= qosEnv->MaxCpus()) {
        GTEST_SKIP() << "Skipping Test: cpu" << cpu << " not available";
    }
    /* should be low priority */
    auto rc = GetTrustyWorkerNice(cpu, &nice);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ(nice, nice_low);

    /* Set high priority*/
    qosEnv->SetPriority(cpu, priority);
    sleep(1);
    rc = GetTrustyWorkerNice(cpu, &nice);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ(nice, nice_expected);

    /* back to low priority */
    qosEnv->SetPriority(cpu, LOW_PRIORITY);
    sleep(1);
    rc = GetTrustyWorkerNice(cpu, &nice);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ(nice, nice_low);
};

INSTANTIATE_TEST_SUITE_P(TrustyQoSTest, TrustyQosTest,
                         testing::Combine(testing::Values(0, 1, 2, 3, 4, 5, 6, 7),
                                          testing::Values(DEFAULT_PRIORITY, HIGH_PRIORITY)),
                         [](const testing::TestParamInfo<TrustyQosTest::ParamType>& info) {
                             std::string name = "cpu" + std::to_string(std::get<0>(info.param)) +
                                                "_pri" + std::to_string(std::get<1>(info.param));
                             return name;
                         });

}  // namespace qos
}  // namespace trusty
}  // namespace android

using android::trusty::qos::qosEnv;
using android::trusty::qos::TrustyQosEnv;

int main(int argc, char** argv) {
    qosEnv = new TrustyQosEnv();
    ::testing::AddGlobalTestEnvironment(qosEnv);
    ::testing::InitGoogleTest(&argc, argv);
    auto status = RUN_ALL_TESTS();
    ALOGI("Test result = %d", status);
    return status;
}
