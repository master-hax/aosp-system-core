/*
 * Copyright (C) 2020 The Android Open Source Project
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

#undef NDEBUG

#include <android-base/unique_fd.h>
#include <assert.h>
#include <log/log.h>
#include <stdlib.h>
#include <trusty/coverage/coverage.h>
#include <trusty/tipc.h>
#include <unistd.h>

using android::base::unique_fd;
using android::trusty::CoverageRecord;

#define TIPC_MAX_MSG_SIZE PAGE_SIZE
#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define TEST_SRV_PORT "com.android.trusty.sancov.test.srv"

__attribute__((section("__libfuzzer_extra_counters"))) uint8_t counters[PAGE_SIZE];

/* libFuzzer function */
namespace fuzzer {
uint8_t* ExtraCountersBegin();
uint8_t* ExtraCountersEnd();
void ClearExtraCounters();
}  // namespace fuzzer

/* Test server's UUID is 77f68803-c514-43ba-bdce-3254531c3d24 */
static struct uuid test_srv_uuid = {
        0x77f68803,
        0xc514,
        0x43ba,
        {0xbd, 0xce, 0x32, 0x54, 0x53, 0x1c, 0x3d, 0x24},
};

static CoverageRecord record(&test_srv_uuid, sizeof(counters));

class TrustyFuzzerExtraCounters {
  public:
    TrustyFuzzerExtraCounters(CoverageRecord* record) : record_(record) {
        assert(fuzzer::ExtraCountersBegin());
        assert(fuzzer::ExtraCountersEnd());

        record_->Open();
        record_->Reset();
        fuzzer::ClearExtraCounters();
    }

    ~TrustyFuzzerExtraCounters() {
        volatile uint8_t* begin = NULL;
        volatile uint8_t* end = NULL;

        record_->Pull();

        auto ret = record_->GetRawData((volatile void**)&begin, (volatile void**)&end);
        assert(ret.ok());

        size_t num_counters = end - begin;
        memcpy(counters, (void*)begin, num_counters);
    }

  private:
    CoverageRecord* record_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static uint8_t buf[TIPC_MAX_MSG_SIZE];

    TrustyFuzzerExtraCounters extra_counters(&record);

    unique_fd test_srv(tipc_connect(TIPC_DEV, TEST_SRV_PORT));
    assert(test_srv >= 0);

    /* Send message to test server */
    int rc = write(test_srv, data, size);
    if (rc < 0) {
        return rc;
    }

    /* Read message from test server */
    rc = read(test_srv, &buf, sizeof(buf));
    if (rc < 0) {
        return rc;
    }

    if (*((uint32_t*)buf) == 0xdeadbeef) {
        abort();
    }

    return 0;
}
