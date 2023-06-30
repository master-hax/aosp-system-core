/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android-base/stringprintf.h>
#include <getopt.h>
#include <trusty/coverage/coverage.h>
#include <trusty/tipc.h>
#include <array>
#include <memory>
#include <vector>

using std::array;
using std::make_unique;
using std::unique_ptr;

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define TEST_SRV_PORT "com.android.trusty.sancov.test.srv"
#define TEST_SRV_MODULE "srv.syms.elf"

#define READ_ONCE(x) (*((volatile __typeof__(x) *) &(x)))
#define WRITE_ONCE(x, val) (*((volatile __typeof__(val) *) &(x)) = (val))

#define FLAG_NONE               0x0
#define FLAG_RUN                0x1
#define FLAG_TOGGLE_CLEAR       0x2

struct control {
    /* Written by controller, read by instrumented TA */
    uint64_t        cntrl_flags;

    /* Written by instrumented TA, read by controller */
    uint64_t        oper_flags;
    uint64_t        write_buffer_start_count;
    uint64_t        write_buffer_complete_count;
};

static const char* dev_name = NULL;

class Controller {
    public:
        void run() {
            connectCoverageServer();
            struct control *control;
            uint64_t complete_cnt = 0, start_cnt = 0;

            while(1) {
                setUpShm();

                for (int index = 0; index < record_list_.size() ; index++) {
                    control = (struct control *)record_list_[index]->getShm();
                    start_cnt = READ_ONCE((control->write_buffer_start_count));
                    complete_cnt = READ_ONCE(control->write_buffer_complete_count);

                    if (complete_cnt != counters[index] && start_cnt == complete_cnt) {
                        WRITE_ONCE(control->cntrl_flags, FLAG_NONE);
                        auto filename = android::base::StringPrintf(
                        "/data/local/tmp/%d.%lu.profraw", index, counters[index]);
                        auto res = record_list_[index]->SaveFile(filename);
                        counters[index]++;
                    }
                    if(complete_cnt == counters[index] && READ_ONCE(control->cntrl_flags) != FLAG_RUN) {
                        WRITE_ONCE(control->cntrl_flags, FLAG_RUN);
                    }
                }
            }
        }

    private:
        std::vector<unique_ptr<android::trusty::coverage::CoverageRecord> >record_list_;
        std::vector<struct uuid >uuid_list_;
        std::vector<uint64_t > counters;
        int coverage_srv_fd;

        void connectCoverageServer() {
            coverage_srv_fd = tipc_connect(TIPC_DEV, LINE_COVERAGE_CLIENT_PORT);
            if (coverage_srv_fd < 0) {
                fprintf(stderr, "Error: Failed to connect to Trusty coverarge server.\n");
                return;
            }
        }

        void setUpShm() {
            struct line_coverage_client_req req;
            struct line_coverage_client_resp resp;
            uint32_t cur_index = record_list_.size();
            req.hdr.cmd = LINE_COVERAGE_CLIENT_CMD_SEND_LIST;
            req.send_list_args.index = cur_index;
            int rc = write(coverage_srv_fd, &req, sizeof(req));
                if (rc != (int)sizeof(req)) {
                    fprintf(stderr, "failed to send request to coverage server: %d\n", rc);
                    return;
            }

            while(1) {
                rc = read(coverage_srv_fd, &resp, sizeof(resp));
                if (rc != (int)sizeof(resp)) {
                    fprintf(stderr, "failed to read reply from coverage server:: %d\n", rc);
                }

                if (resp.hdr.cmd == (LINE_COVERAGE_CLIENT_CMD_OPEN | LINE_COVERAGE_CLIENT_CMD_RESP_BIT)) {
                    break;
                }

                if (resp.hdr.cmd == (req.hdr.cmd | LINE_COVERAGE_CLIENT_CMD_RESP_BIT)) {
                    uuid_list_.push_back(resp.send_list_args.uuid);
                    record_list_.push_back(make_unique<android::trusty::coverage::CoverageRecord>(TIPC_DEV, &uuid_list_.back()));
                    counters.push_back(0);
                    record_list_.back()->Open(coverage_srv_fd);
                }

                else {
                    fprintf(stderr, "Unknown response header\n");
                }
                cur_index++;
                req.hdr.cmd = LINE_COVERAGE_CLIENT_CMD_SEND_LIST;
                req.send_list_args.index = cur_index;
                int rc = write(coverage_srv_fd, &req, sizeof(req));
                    if (rc != (int)sizeof(req)) {
                        fprintf(stderr, " failed to send request to coverage server:: %d\n", rc);
                }
            }
        }

};

int main() {
    int rc = 0;
    dev_name = TIPC_DEV;
    Controller cur;
    cur.run();

    return EXIT_SUCCESS;
}
