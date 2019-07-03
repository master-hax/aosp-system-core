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

#include <fcntl.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <functional>
#include <numeric>
#include <iostream>
#include <map>
#include <thread>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <fstab/fstab.h>
#include <fs_mgr_dm_linear.h>
#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libdm/loop_control.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>
#include <openssl/sha.h>
#include "test_util.h"

#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE 32
#endif

using namespace std;
using namespace std::chrono_literals;
using namespace std::placeholders;
using namespace android::dm;
using unique_fd = android::base::unique_fd;
using namespace std::string_literals;
using namespace android::fs_mgr;

const static char* kSuper = "/dev/block/by-name/super";
const static char* kRandom = "/dev/urandom";
const static char* kMemInfo = "/proc/meminfo";
const static char* kDropCaches = "/proc/sys/vm/drop_caches";
const static char* kCpuPath = "/sys/devices/system/cpu/";
const static size_t kSectorSize = 512;
const static auto kMapTimeout = 3000ms;
const static size_t kRandReadTimes = 1000;
const static auto kMemPollTime = 50ms;

// Row tags
// Sample mean
const static char* kAverageRow = "SampMean";
// Uncorrected sample standard deviation, or standard deviation of the sample
// https://en.wikipedia.org/wiki/Standard_deviation#Uncorrected_sample_standard_deviation
const static char* kSdRow = "PopSd";
// (Corrected) Sample standard deviation
// https://en.wikipedia.org/wiki/Standard_deviation#Corrected_sample_standard_deviation
const static char* kSampleSdRow = "SampSd";
const static char* kMinMemFreeRow = "MinFree";
const static char* kMaxMemFreeRow = "MaxFree";
const static char* kMinMemAvailRow = "MinAvail";
const static char* kMaxMemAvailRow = "MaxAvail";
const static char* kSpecialRows[] = {
    kAverageRow, kSdRow, kSampleSdRow, kMinMemFreeRow, kMaxMemFreeRow, kMinMemAvailRow, kMaxMemAvailRow
};
const static size_t kMinTagWidth = 6;
const static size_t kColumnGap = 1;

DEFINE_int32(times, 1, "Number of iterations of test");

unsigned long long operator""_MiB(unsigned long long v) {
    return v << 20;
}

unsigned long long operator""_GiB(unsigned long long v) {
    return v << 30;
}

const static size_t kCowSlackSize = 200_MiB;
const static size_t kNoCowSize = 0;
const static size_t kAutoCowSize = ((size_t)-1);

// poor man's truncation of double values
std::string ToString(const std::string& s, size_t width) {
    return s.substr(0, std::min(s.size(), width));
}
std::string ToString(double d, size_t width) {
    return ToString(std::to_string(d), width);
}

template<typename T>
std::pair<std::string, std::string> GetSizeStringImpl(T size) {
    for (const auto& unit : {"", "K", "M", "G"}) {
        if (size < 1024) {
            return {std::to_string(size), unit};
        }
        size /= 1024;
    }
    return {std::to_string(size), "T"};
}
std::string GetSizeString(size_t size) {
    auto [num, unit] = GetSizeStringImpl(size);
    return num + unit;
}
std::string GetSizeString(double size) {
    auto [num, unit] = GetSizeStringImpl(size);
    return ToString(num, kMinTagWidth - unit.size()) + unit;
}
size_t ParseSizeString(const std::string& s) {
    std::stringstream ss(s);
    size_t count;
    std::string unit;
    ss >> count;
    std::getline(ss, unit);

    if (unit.empty()) {
      return count;
    }
    for (char e : {'k', 'm', 'g'}) {
      count *= 1024;
      if (unit[0] == e || unit[0] == toupper(e)) {
        return count;
      }
    }
    return SIZE_MAX;
}

struct SnapshotInfo {
    std::unique_ptr<TempDevice> base;
    std::unique_ptr<TempDevice> cow;
    std::unique_ptr<TempDevice> snapshot;

    ~SnapshotInfo() {
        // teardown snapshot first
        snapshot = nullptr;
        // Then COW and base.
        cow = nullptr;
        base = nullptr;
    }

    static std::unique_ptr<SnapshotInfo> PrepareTargetPartition(
            const std::string& name, size_t device_size, size_t cow_size) {
        DeleteDevicesForPartition(name);

        auto info = std::make_unique<SnapshotInfo>();
        auto base_name = name + "_base" + fs_mgr_get_other_slot_suffix();
        auto cow_name = name + "_cow" + fs_mgr_get_other_slot_suffix();
        auto snapshot_name = name + "_snapshot" + fs_mgr_get_other_slot_suffix();

        // Create base.
        auto builder = MetadataBuilder::New(kSuper, android::fs_mgr::SlotNumberForSlotSuffix(fs_mgr_get_slot_suffix()));
        if (!builder) {
            std::cerr << "Can't create metadata builder\n";
            return nullptr;
        }

        auto groups = builder->ListGroups();
        for (const auto& group : groups) {
            if (android::base::EndsWith(group, fs_mgr_get_other_slot_suffix())) {
                builder->RemoveGroupAndPartitions(group);
            }
        }

        auto partition = builder->FindPartition(base_name);
        if (!partition)
            partition = builder->AddPartition(base_name, 0);
        if (!partition) {
            std::cerr << "Can't create partition " << base_name << "\n";
            return nullptr;
        }
        builder->ResizePartition(partition, device_size);

        if (cow_size != kNoCowSize) {
            if (cow_size == kAutoCowSize) cow_size = device_size + kCowSlackSize;
            partition = builder->FindPartition(cow_name);
            if (!partition)
                partition = builder->AddPartition(cow_name, 0);
            if (!partition) {
                std::cerr << "Can't create partition " << cow_name << "\n";
                return nullptr;
            }
            builder->ResizePartition(partition, cow_size);
        }

        auto metadata = builder->Export();
        if (!metadata) {
            std::cerr << "Can't export\n";
            return nullptr;
        }

        std::string path;
        if (!CreateLogicalPartition(kSuper, *metadata, base_name, true /* force_writable */,
                                    kMapTimeout, &path)) {
            std::cerr << "Can't map " << base_name << "\n";
            return nullptr;
        }
        info->base = std::make_unique<TempDevice>(base_name);

        // kNoCowSize means we don't need to snapshot it.
        if (cow_size == kNoCowSize) {
            // std::cout << "\nFor " << name << ": " << info->base->path() << "\n";
            // std::cout.flush();
            return info;
        }

        if (!CreateLogicalPartition(kSuper, *metadata, cow_name, true /* force_writable */,
                                    kMapTimeout, &path)) {
            std::cerr << "Can't map " << cow_name << "\n";
            return nullptr;
        }
        info->cow = std::make_unique<TempDevice>(cow_name);

        // Zero out cow device
        {
            unique_fd cow_fd(TEMP_FAILURE_RETRY(open(info->cow->path().c_str(), O_WRONLY | O_BINARY)));
            char zeros[4096] = {0};
            while(android::base::WriteFully(cow_fd, zeros, sizeof(zeros)))
                ;
        }

        LOG(WARNING) << "base:" << info->base->path();
        LOG(WARNING) << "cow:" << info->cow->path();

        // std::cout << "\nFor " << name << ":\n  base=" << info->base->path() << "\n  cow =" << info->cow->path() << "\n";
        // std::cout.flush();

        // Hack to make COW working
        // not needed anymore
        // std::string buf(4096, '\0');
        // EXPECT_TRUE(android::base::WriteStringToFile(buf, info->cow->path(), false));

        DmTable snap_table;
        EXPECT_TRUE(snap_table.AddTarget(make_unique<DmTargetSnapshot>(
                0, device_size / kSectorSize, info->base->path(), info->cow->path(),
                SnapshotStorageMode::Persistent, 8)));
        EXPECT_TRUE(snap_table.valid());

        info->snapshot = std::make_unique<TempDevice>(snapshot_name, snap_table);
        EXPECT_TRUE(info->snapshot->valid());
        EXPECT_FALSE(info->snapshot->path().empty());
        EXPECT_TRUE(info->snapshot->valid() && info->snapshot->WaitForUdev());

        LOG(WARNING) << "snapshot:" << info->snapshot->path();

        // std::cout << "\nFor " << name << ":\n  base=" << info->base->path() << "\n  cow =" << info->cow->device() << "\n  snap=" << info->snapshot->path() << "\n";
        // std::cout.flush();

        return info;
    }

    static std::unique_ptr<SnapshotInfo> ForPartition(const std::string& name) {
        auto info = std::make_unique<SnapshotInfo>();
        info->base = std::make_unique<TempDevice>(name + "_base" + fs_mgr_get_other_slot_suffix());
        info->cow = std::make_unique<TempDevice>(name + "_cow" + fs_mgr_get_other_slot_suffix());
        info->snapshot = std::make_unique<TempDevice>(name + "_snapshot" + fs_mgr_get_other_slot_suffix());
        if (!info->base->valid()) info->base = nullptr;
        if (!info->cow->valid()) info->cow = nullptr;
        if (!info->snapshot->valid()) info->snapshot = nullptr;
        return info;
    }

    void ForEach(const std::function<void(TempDevice*)>& func) const {
        if (snapshot) func(snapshot.get());
        if (base) func(base.get());
        if (cow) func(cow.get());
    }

    static void DeleteDevicesForPartition(const std::string& name) {
        // Delete previous devices if the test was interrupted and devices aren't properly
        // cleaned up. Snapshot needs to be deleted first.
        auto info = ForPartition(name);
        info->ForEach([](auto* device) {
            ASSERT_TRUE(device->Destroy());
        });
        info = nullptr;

        info = ForPartition(name);
        info->ForEach([](auto* device) {
            FAIL() << device->name() << " should have been destroyed";
        });
    }


    // Device to write to. Can be either base or snapshot.
    TempDevice* target() const {
        return snapshot ? snapshot.get() : base.get();
    };

    size_t base_size() const {
        if (!base) return 0;
        unique_fd base_fd(TEMP_FAILURE_RETRY(open(base->path().c_str(), O_RDONLY)));
        return lseek64(base_fd, 0, SEEK_END);
    }

    void InitiateMerge() const {
        ASSERT_NE(nullptr, base);
        ASSERT_NE(nullptr, cow);
        ASSERT_NE(nullptr, snapshot);
        DmTable merge_table;
        ASSERT_TRUE(merge_table.AddTarget(make_unique<DmTargetSnapshot>(
                0, base_size() / kSectorSize, base->path(), cow->path(),
                SnapshotStorageMode::Merge, 8)));
        ASSERT_TRUE(merge_table.valid());
        ASSERT_TRUE(DeviceMapper::Instance().LoadTableAndActivate(snapshot->name(), merge_table));
    }

    void WaitMergeComplete() const {
        ASSERT_NE(nullptr, snapshot);
        while (true) {
            vector<DeviceMapper::TargetInfo> status;
            ASSERT_TRUE(DeviceMapper::Instance().GetTableStatus(snapshot->name(), &status));
            ASSERT_EQ(1u, status.size());
            ASSERT_EQ("snapshot-merge"s, status[0].spec.target_type);

            DmTargetSnapshot::Status merge_status;
            ASSERT_TRUE(DmTargetSnapshot::ParseStatusText(status[0].data, &merge_status));
            ASSERT_TRUE(merge_status.error.empty());
            if (merge_status.sectors_allocated == merge_status.metadata_sectors) {
                break;
            }

            std::this_thread::sleep_for(100ms);
        }
    }

    void Collapse() {
        ASSERT_NE(nullptr, cow);
        ASSERT_NE(nullptr, snapshot);

        // Poor-man's implementation of collapse; in reality we'll need to
        // dm.LoadTableAndActivate(snapshot->name(), dm.table(base->name()))

        ASSERT_TRUE(snapshot->Destroy());
        snapshot = nullptr;

        ASSERT_TRUE(cow->Destroy());
        cow = nullptr;

        // Now, target() will return base.
    }

    void MergeAndWait() {
        InitiateMerge();
        WaitMergeComplete();
        Collapse();
    }

    void Release() {
        if (base) base->Release();
        if (cow) cow->Release();
        if (snapshot) snapshot->Release();
    }

    void Dump() const {
        DumpDevice(base);
        DumpDevice(cow);
        DumpDevice(snapshot);
    }
    static void DumpDevice(const std::unique_ptr<TempDevice>& dev) {
        if (dev == nullptr) return;
        std::cout << dev->name();
        std::vector<DeviceMapper::TargetInfo> table;
        if (!DeviceMapper::Instance().GetTableInfo(dev->name(), &table)) {
            std::cout << ": unknown\n";
            return;
        }
        std::cout << ": [";
        for (const auto& target: table) {
            if (&target != &*table.begin()) std::cout << "; ";
            std::cout << target.spec.sector_start << "-"
                      << (target.spec.sector_start + target.spec.length) << ": "
                      << target.spec.target_type;
            if (!target.data.empty()) std::cout << ", " << target.data;
        }
        std::cout << "]\n";
    }
};

bool ForFd(android::base::borrowed_fd fd,
           std::function<bool(char* buf, size_t len)> func,
           const std::pair<size_t, size_t>& range = {0, SIZE_MAX}) {
    if (lseek64(fd.get(), range.first, SEEK_SET) != 0) {
        return false;
    }
    char buf[4096];
    size_t end = range.first;
    ssize_t bytes_read;
    while ((bytes_read = TEMP_FAILURE_RETRY(read(fd.get(), &buf, std::min(sizeof(buf), range.second - end)))) > 0) {
        if (!func(buf, (size_t)bytes_read)) {
            return true;
        }
        end += bytes_read;
    }
    return true;
}

std::string Sha256Fd(android::base::borrowed_fd fd,
                     const std::pair<size_t, size_t>& range = {0, SIZE_MAX}) {
    char digest[SHA256_DIGEST_SIZE];
    SHA256_CTX sha;
    SHA256_Init(&sha);
    auto update = [&sha] (auto buf, auto len) {
        SHA256_Update(&sha, (unsigned char*)buf, len);
        return true; // continue
    };
    if (!ForFd(fd, update, range))
        return {};
    SHA256_Final((unsigned char*)digest, &sha);

    std::string ret(SHA256_DIGEST_SIZE * 2, '\0');
    for(int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        sprintf(&ret[i * 2], "%02x", digest[i]);
    }
    return ret;
}


class PrintingTimer : public android::base::Timer {
   public:
    explicit PrintingTimer(bool silent = false) : silent_(silent) {};
    void Checkpoint(const std::string& tag) {
        std::chrono::milliseconds duration_since_start = duration();
        if (!silent_) {
            std::cout << "[TIME] " << tag << ": "
                      << (duration_since_start - last_print_).count() << "ms ("
                      << duration_since_start.count() << "ms since start)\n";
            std::cout.flush();
        }
        durations_.emplace_back(tag, duration_since_start - last_print_);
        last_print_ = duration_since_start;
    }
    void StoreTotal() {
        durations_.emplace_back("total", last_print_);
    }

    static void PrintRow(const size_t first_cell_width,
                         const std::string& first_cell,
                         const std::vector<size_t>& rest_widths,
                         const std::function<void(std::ostream&, size_t)>& rest_func) {
        std::cout << std::setw(first_cell_width) << first_cell;
        for (size_t column = 0; column < rest_widths.size(); ++column) {
            std::cout << std::setw(kColumnGap) << " ";
            std::cout << std::setw(std::max(kMinTagWidth, rest_widths[column])) << std::right;
            rest_func(std::cout, column);
        }
        std::cout << "\n";
    }

    static size_t GetNumberWidth(size_t timers_count) {
        return std::max<size_t>(
            std::to_string(timers_count).size(),
            strlen(*std::max_element(&kSpecialRows[0], &kSpecialRows[arraysize(kSpecialRows)], [] (auto a, auto b) {
                return strlen(a) < strlen(b);
            })));
    }
    std::vector<size_t> GetColumnWidths() const {
        std::vector<size_t> column_widths;
        for (const auto& pair : durations_) {
            column_widths.push_back(pair.first.size());
        }
        return column_widths;
    }

    void PrintTitle(size_t timers_count) const {
        PrintRow(GetNumberWidth(timers_count), "#", GetColumnWidths(), [&] (auto& os, auto column) {
            os << durations_[column].first;
        });
    }

    void Print(size_t row, size_t timers_count) const {
        if (row == 0) PrintTitle(timers_count);
        PrintRow(GetNumberWidth(timers_count), std::to_string(row), GetColumnWidths(), [&] (auto& os, auto column) {
            os << durations_[column].second.count();
        });
    }

    static void PrintSummary(const std::vector<PrintingTimer>& timers) {
        if (timers.size() <= 1) return;

        auto number_width = GetNumberWidth(timers.size());
        auto column_widths = timers[0].GetColumnWidths();

        std::vector<double> averages;
        std::vector<double> pop_sds;
        std::vector<double> sample_sds;
        for (size_t column = 0; column < column_widths.size(); ++column) {
            double sum = 0;
            double sum_of_squares = 0;
            for (const auto& timer : timers) {
                size_t cell = timer.durations_[column].second.count();
                sum += cell;
                sum_of_squares += (cell * cell);
            }

            double average = sum / timers.size();
            double pop_variance = (sum_of_squares / timers.size()) - average * average;

            averages.push_back(average);
            pop_sds.push_back(sqrt(pop_variance));
            sample_sds.push_back(sqrt(pop_variance * timers.size() / (timers.size() - 1)));
        }

        PrintRow(number_width, kAverageRow, column_widths, [&] (auto& os, auto column) {
            os << ToString(averages[column], kMinTagWidth);
        });
        PrintRow(number_width, kSdRow, column_widths, [&] (auto& os, auto column) {
            os << ToString(pop_sds[column], kMinTagWidth);
        });
        PrintRow(number_width, kSampleSdRow, column_widths, [&] (auto& os, auto column) {
            os << ToString(sample_sds[column], kMinTagWidth);
        });
    }
   private:
    bool silent_;
    std::chrono::milliseconds last_print_{0};
    std::vector<std::pair<std::string, std::chrono::milliseconds>> durations_;
    PrintingTimer FakeInitValue() const {
        PrintingTimer ret(*this);
        for (auto& pair : ret.durations_) pair = {pair.first, 0ms};
        return ret;
    }
};

void PrintNow() {
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::cout << std::put_time(std::localtime(&now_c), "%F %T");
}

struct MemRecord {
    size_t min_mem_free = SIZE_MAX, max_mem_free = 0, min_mem_avail = SIZE_MAX, max_mem_avail = 0;

    void Update(size_t mem_free, size_t mem_available) {
        min_mem_free = std::min(min_mem_free, mem_free);
        max_mem_free = std::max(max_mem_free, mem_free);
        min_mem_avail = std::min(min_mem_avail, mem_available);
        max_mem_avail = std::max(max_mem_avail, mem_available);
    }
    void Merge(const MemRecord& other) {
        min_mem_free = std::min(min_mem_free, other.min_mem_free);
        max_mem_free = std::max(max_mem_free, other.max_mem_free);
        min_mem_avail = std::min(min_mem_avail, other.min_mem_avail);
        max_mem_avail = std::max(max_mem_avail, other.max_mem_avail);
    }

    static void PrintSummary(const std::vector<PrintingTimer>& timers,
                             const std::vector<std::vector<MemRecord>>& mem_records) {
        std::vector<MemRecord> merged_mem_records;
        for (size_t column = 0; column < mem_records[0].size(); ++column) {
            MemRecord& column_sum = merged_mem_records.emplace_back();
            for (const auto& row : mem_records) {
                column_sum.Merge(row[column]);
            }
        }

        MemRecord total;
        for (const auto& cell : merged_mem_records) {
            total.Merge(cell);
        }
        merged_mem_records.emplace_back(std::move(total));

        PrintingTimer::PrintRow(PrintingTimer::GetNumberWidth(timers.size()),
                                kMinMemFreeRow,
                                timers[0].GetColumnWidths(),
                                [&](auto& os, auto column) {
                                    os << GetSizeString((double)(merged_mem_records[column].min_mem_free * 1024));
                                });
        PrintingTimer::PrintRow(PrintingTimer::GetNumberWidth(timers.size()),
                                kMaxMemFreeRow,
                                timers[0].GetColumnWidths(),
                                [&](auto& os, auto column) {
                                    os << GetSizeString((double)(merged_mem_records[column].max_mem_free * 1024));
                                });
        PrintingTimer::PrintRow(PrintingTimer::GetNumberWidth(timers.size()),
                                kMinMemAvailRow,
                                timers[0].GetColumnWidths(),
                                [&](auto& os, auto column) {
                                    os << GetSizeString((double)(merged_mem_records[column].min_mem_avail * 1024));
                                });
        PrintingTimer::PrintRow(PrintingTimer::GetNumberWidth(timers.size()),
                                kMaxMemAvailRow,
                                timers[0].GetColumnWidths(),
                                [&](auto& os, auto column) {
                                    os << GetSizeString((double)(merged_mem_records[column].max_mem_avail * 1024));
                                });
    }
};

struct MemRecorder {
    MemRecorder() : thread_(std::thread(std::bind(&MemRecorder::Run, this))) {
    }
    ~MemRecorder() {
        stop_ = true;
        thread_.join();
    }
    MemRecord Checkpoint() {
        std::unique_lock<std::mutex> lock(data_mutex_);
        MemRecord ret = data_;
        data_ = {};
        return ret;
    }
   private:
    void Run() {
        while (!stop_) {
            Record();
            std::this_thread::sleep_for(kMemPollTime);
        }
    }
    void Record() {
        char buf[120];
        ASSERT_TRUE(android::base::ReadFully(TEMP_FAILURE_RETRY(open(kMemInfo, O_RDONLY)), buf, sizeof(buf)));

        size_t mem_total = 0, mem_free = 0, mem_available = 0;
        ASSERT_EQ(3, sscanf(buf, "MemTotal: %zu kB MemFree: %zu kB MemAvailable: %zu kB",
               &mem_total, &mem_free, &mem_available));

        std::unique_lock<std::mutex> lock(data_mutex_);
        data_.Update(mem_free, mem_available);
    }

    std::thread thread_;
    std::atomic_bool stop_{false};

    std::mutex data_mutex_;
    MemRecord data_;
} gMemRecorder;

// See toolbox, start.cpp
void StopService(const std::string& service) {
    android::base::SetProperty("ctl.stop", service);
}

// See toolbox, start.cpp
void StopAndroid() {
    std::vector<std::string> services = {"netd", "surfaceflinger", "zygote"};

    // Only start zygote_secondary if not single arch.
    std::string zygote_configuration = android::base::GetProperty("ro.zygote", "");
    if (zygote_configuration != "zygote32" && zygote_configuration != "zygote64") {
        services.emplace_back("zygote_secondary");
    }

    for (auto it = services.crbegin(); it != services.crend(); ++it) {
        StopService(*it);
    }
}

// Magic scripts from https://docs.google.com/document/d/1Dw_mClBSXr9HUKYV0594ykT74_ldWY-Op652rMfRCC8/edit#heading=h.30fo5k52h8s8
void DropCaches() {
    ASSERT_TRUE(android::base::WriteStringToFile("3", kDropCaches));
}

void PinCpus() {
    StopService("mpdecision");

    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(kCpuPath), closedir);
    ASSERT_NE(nullptr, dir);
    dirent* dp;
    while ((dp = readdir(dir.get())) != nullptr) {
        int cpunum;
        if (sscanf(dp->d_name, "cpu%d", &cpunum) == 1) {
            ASSERT_TRUE(android::base::WriteStringToFile("1", std::string(kCpuPath) + dp->d_name + "/online"));
            ASSERT_TRUE(android::base::WriteStringToFile("performance", std::string(kCpuPath) + dp->d_name + "/cpufreq/scaling_governor"));
        }
    }
}

struct TargetReaderWriter {
    virtual ~TargetReaderWriter() = default;
    virtual bool ShouldVerify() const;
    virtual void Write(android::base::borrowed_fd source_fd, const std::string& target_path) const = 0;
    void SeqRead(const std::string& target_path) const {

        // Drop caches before the read so that the measurement is more accurate.
        DropCaches();

        unique_fd target_fd(TEMP_FAILURE_RETRY(open(target_path.c_str(), O_RDONLY)));
        ASSERT_NE(-1, target_fd.get()) << "Can't open " << target_path;
        ForFd(target_fd, [] (auto, auto) { return true; });
    }

    void RandRead(const std::string& target_path, size_t max_size,
                  size_t bytes_each_read = kSectorSize,
                  size_t times = 100000,
                  unsigned seed = 1) const {

        // Drop caches before the read so that the measurement is more accurate.
        DropCaches();

        unique_fd target_fd(TEMP_FAILURE_RETRY(open(target_path.c_str(), O_RDONLY)));
        ASSERT_NE(-1, target_fd.get()) << "Can't open " << target_path;
        size_t unit_count = max_size / bytes_each_read;
        srandom(seed);
        auto buf = std::make_unique<char[]>(bytes_each_read);
        for (size_t time = 0; time < times; ++time) {
            size_t unit_number = random() % unit_count;
            lseek64(target_fd.get(), unit_number * bytes_each_read, SEEK_SET);
            ASSERT_TRUE(ReadFully(target_fd, buf.get(), bytes_each_read));
        }
    }

    std::string Hash(const std::string& target_path) const {
        unique_fd target_fd(TEMP_FAILURE_RETRY(open(target_path.c_str(), O_RDONLY)));
        if (target_fd.get() == -1) {
            ADD_FAILURE() << "Can't open " << target_path;
            return "";
        }
        return Sha256Fd(target_fd);
    }
};

struct CopySourceToTarget : public TargetReaderWriter {
    bool ShouldVerify() const { return true; }
    void Write(android::base::borrowed_fd source_fd, const std::string& target_path) const override {

        // Drop caches before the write so that the measurement is more accurate.
        DropCaches();

        // std::cout << "copying " << source << " -> " << target << endl;
        unique_fd target_fd(TEMP_FAILURE_RETRY(open(target_path.c_str(), O_WRONLY | O_BINARY)));
        ASSERT_NE(-1, target_fd.get()) << "Can't open " << target_path;
        ForFd(source_fd, [&](auto buf, auto len) {
            if (!android::base::WriteFully(target_fd.get(), buf, len)) {
                ADD_FAILURE() << strerror(errno);
                return false; // stop
            }
            return true; // continue
        });
        EXPECT_EQ(0, fsync(target_fd.get())) << strerror(errno);
    }

};

struct WriteRandomToTarget : public TargetReaderWriter {
    bool ShouldVerify() const { return false; }
    void Write(android::base::borrowed_fd source_fd, const std::string& target_path) const override {

        // Drop caches before the write so that the measurement is more accurate.
        DropCaches();

        unique_fd target_fd(TEMP_FAILURE_RETRY(open(target_path.c_str(), O_WRONLY | O_BINARY)));
        ASSERT_NE(-1, target_fd.get()) << "Can't open " << target_path;
        unique_fd random_fd(TEMP_FAILURE_RETRY(open(kRandom, O_RDONLY)));
        ASSERT_NE(-1, random_fd.get()) << "Can't open " << kRandom;

        ForFd(source_fd, [&](auto buf, auto len) {
            if (!android::base::ReadFully(random_fd.get(), buf, len)) {
                ADD_FAILURE() << strerror(errno);
                return false; // stop
            }
            if (!android::base::WriteFully(target_fd.get(), buf, len)) {
                ADD_FAILURE() << strerror(errno);
                return false; // stop
            }
            return true; // continue
        });
        EXPECT_EQ(0, fsync(target_fd.get())) << strerror(errno);
    }
};

class LibSnapshotBenchmark : public ::testing::TestWithParam<const char* /* name */> {
public:
    void SetUp() override {
        SnapshotInfo::DeleteDevicesForPartition(GetParam());

        StopAndroid();
        PinCpus();
        DropCaches();
    }

    static std::string GetSourcePartitionDevice(const std::string& name) {
        std::string path;
        EXPECT_TRUE(DeviceMapper::Instance().GetDmDevicePathByName(
            name + fs_mgr_get_slot_suffix(), &path));
        return path;
    }

    static void TestCopyAndVerify(const std::string& name, size_t repeat_times,
                           const std::function<std::unique_ptr<SnapshotInfo>(const std::string&, size_t)>& target_opener,
                           const TargetReaderWriter& target_reader_writer,
                           const std::function<void(SnapshotInfo*)>& target_merger) {

        auto source = GetSourcePartitionDevice(name);
        unique_fd source_fd(TEMP_FAILURE_RETRY(open(source.c_str(), O_RDONLY)));
        auto source_size = lseek64(source_fd.get(), 0, SEEK_END);
        ASSERT_GE(source_size, 0);
        std::cout << name << " source (" << source << "): " << source_size << " Bytes (" << GetSizeString((double)source_size) << ")\n";

        std::cout << "Computing hash of " << name << " source partition...\r";
        auto source_sha = Sha256Fd(source_fd);
        // std::cout << name << " source (" << source << "): " << source_sha << std::endl;

        std::vector<PrintingTimer> timers;
        std::vector<std::vector<MemRecord>> mem_records;
        for (size_t invocation = 0; invocation < repeat_times; ++invocation) {
            std::cout << "Invocation #" << invocation << " started at ";
            PrintNow();
            std::cout << "\r";
            std::cout.flush();

            PrintingTimer& timer = timers.emplace_back(true /* silent */);
            std::vector<MemRecord>& row_mem_record = mem_records.emplace_back();
            gMemRecorder.Checkpoint();

            auto checkpoint = [&] (const auto& tag) {
                timer.Checkpoint(tag);
                row_mem_record.push_back(gMemRecorder.Checkpoint());
            };

            auto info = target_opener(name, source_size);
            ASSERT_NE(nullptr, info);
            if (invocation == 0) info->Dump();
            checkpoint("prepare");

            std::string target = info->target()->path();
            ASSERT_FALSE(target.empty());

            target_reader_writer.Write(source_fd, target);
            checkpoint("write");

            target_reader_writer.SeqRead(target);
            checkpoint("seq_r");

            target_reader_writer.SeqRead(info->base->path());
            checkpoint("seq_r_b");

            for (size_t bytes_each_read = 512;
                 bytes_each_read <= 16_MiB;
                 bytes_each_read = bytes_each_read << 3) {

                target_reader_writer.RandRead(target, source_size, bytes_each_read,
                                              kRandReadTimes,
                                              bytes_each_read /* seed */);
                checkpoint("rr" + GetSizeString(bytes_each_read));
            }

            auto sha_before_merge = target_reader_writer.Hash(target);
            EXPECT_TRUE(!target_reader_writer.ShouldVerify() || source_sha == sha_before_merge);
            checkpoint("verify");

            if (target_merger) {
                target_merger(info.get());
                checkpoint("merge");

                // Change target to the base device because we didn't replace the table of
                // snapshot-merge with the table of base, but just replace it at the application level.
                target = info->target()->path();

                target_reader_writer.SeqRead(target);
                checkpoint("seq_r");

                for (size_t bytes_each_read = 512;
                     bytes_each_read <= 16_MiB;
                     bytes_each_read = bytes_each_read << 3) {

                    target_reader_writer.RandRead(target, source_size, bytes_each_read,
                                                  kRandReadTimes,
                                                  bytes_each_read /* seed */);
                    checkpoint("rr" + GetSizeString(bytes_each_read));
                }

                auto sha_after_merge = target_reader_writer.Hash(target);
                EXPECT_EQ(sha_before_merge, sha_after_merge);
                checkpoint("verify");
            }

            timer.StoreTotal();
            timer.Print(invocation, repeat_times);
        }
        PrintingTimer::PrintSummary(timers);
        MemRecord::PrintSummary(timers, mem_records);
    }
};

TEST_P(LibSnapshotBenchmark, CopyToDmSnapshot) {
    TestCopyAndVerify(GetParam(), FLAGS_times,
        std::bind(&SnapshotInfo::PrepareTargetPartition, _1, _2, kAutoCowSize),
        CopySourceToTarget(),
        std::bind(&SnapshotInfo::MergeAndWait, _1));
}

TEST_P(LibSnapshotBenchmark, CopyToDmLinear) {
    TestCopyAndVerify(GetParam(), FLAGS_times,
        std::bind(&SnapshotInfo::PrepareTargetPartition, _1, _2, kNoCowSize),
        CopySourceToTarget(),
        nullptr);
}

TEST_P(LibSnapshotBenchmark, WriteRandomToDmSnapshot) {
    TestCopyAndVerify(GetParam(), FLAGS_times,
        std::bind(&SnapshotInfo::PrepareTargetPartition, _1, _2, kAutoCowSize),
        WriteRandomToTarget(),
        std::bind(&SnapshotInfo::MergeAndWait, _1));
}

TEST_P(LibSnapshotBenchmark, WriteRandomToDmLinear) {
    TestCopyAndVerify(GetParam(), FLAGS_times,
        std::bind(&SnapshotInfo::PrepareTargetPartition, _1, _2, kNoCowSize),
        WriteRandomToTarget(),
        nullptr);
}

INSTANTIATE_TEST_SUITE_P(Vendor, LibSnapshotBenchmark,
                         ::testing::Values("vendor"));

namespace fio {
DEFINE_bool(fio, false, "Skip all tests and modify state of 'fio' device.");
DEFINE_bool(setup, false,
            "Skip all tests, destroy existing 'fio' device, and set up new 'fio' device for FIO\n"
            " testing");
DEFINE_bool(merge, false,
            "Merge existing 'fio' dm-snapshot device");
DEFINE_bool(teardown, false,
            "Destroy existing 'fio' device");
DEFINE_string(device_size, "0" /* GetSizeString(0) */,
              "Size of base device. Only valid for --setup.");
DEFINE_string(cow_size, "0" /* GetSizeString(kNoCowSize) */,
              "Size of COW device. Only valid for --setup. If missing, COW and snapshot devices\n"
              "aren't created.");

const static char* kFioDeviceName = "fio";

int Setup() {
    auto device_size = ParseSizeString(FLAGS_device_size);
    auto cow_size = ParseSizeString(FLAGS_cow_size);

    SnapshotInfo::DeleteDevicesForPartition(kFioDeviceName);

    if (device_size == 0) {
        std::cerr << "Invalid device size\n";
        return 1;
    }

    auto info = SnapshotInfo::PrepareTargetPartition(
                kFioDeviceName,
                device_size,
                cow_size);
    if (!info) {
        std::cerr << "Cannot setup devices\n";
        return 1;
    }

    std::cout << "base=" << info->base->path() << "\n";
    std::cout << "base_size=" << info->base_size() << "\n";
    if (info->cow) {

        std::cout << "cow=" << info->cow->path() << "\n";

        unique_fd cow_fd(TEMP_FAILURE_RETRY(open(info->cow->path().c_str(), O_RDONLY)));
        std::cout << "cow_size=" << lseek64(cow_fd, 0, SEEK_END) << "\n";
    }
    if (info->snapshot)
        std::cout << "snapshot=" << info->snapshot->path() << "\n";

    info->Release();
    return 0;
}

int Teardown() {
    SnapshotInfo::DeleteDevicesForPartition(kFioDeviceName);
    return 0;
}

int Merge() {
    auto info = SnapshotInfo::ForPartition(kFioDeviceName);
    info->MergeAndWait();
    std::cout << "merged=" << info->base->path() << "\n";
    info->Release();
    return 0;
}

} // namespace fio

int main(int argc, char **argv) {
    gflags::AllowCommandLineReparsing();
    gflags::ParseCommandLineFlags(&argc, &argv, false);

    if (fio::FLAGS_setup) {
        return fio::Setup();
    }
    if (fio::FLAGS_merge) {
        return fio::Merge();
    }
    if (fio::FLAGS_teardown) {
        return fio::Teardown();
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
