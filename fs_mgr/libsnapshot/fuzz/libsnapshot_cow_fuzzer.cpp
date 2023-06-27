/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache license, Version 2.0 (the "license");
 * you may not use this file except in compliance with the license.
 * You may obtain a copy of the license at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the license is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the license for the specific language governing permissions and
 * limitations under the license.
 *
 */

#include <android-base/file.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <writer_v2.h>

using namespace android;
using namespace snapshot;

constexpr int32_t kStringLength = 32;
constexpr int32_t kMinStartSize = 1;
constexpr int32_t kMinSize = 0;
constexpr int32_t kMaxSize = 1000;
constexpr int32_t kMinVersion = 0;
constexpr int32_t kMaxVersion = 3;
constexpr int32_t kMinThread = 0;
constexpr int32_t kMaxThread = 2;
constexpr int32_t kMinBlockSize = 17;
constexpr int32_t kMaxOpsSize = 100;
constexpr int32_t kDefault = 0;
constexpr int32_t kUserspaceMerge = 1;
const std::string kCompressionMethods[] = {"gz", "brotli", "lz4", "zstd", "none"};
const char kNullChar = '\0';

class SnapShotCowFuzzer {
  public:
    SnapShotCowFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void invokeRead();
    void invokeWrite();
    void fillOptions();
    bool initWriter();
    bool initReader();

    bool mFinalizedStatus;
    FuzzedDataProvider mFdp;
    std::unique_ptr<TemporaryFile> mCow;
    std::unique_ptr<CowWriterV2> mCowWriter;
    std::unique_ptr<ICowWriter> mICowWriter;
    std::unique_ptr<CowReader> mCowReader;
    android::snapshot::CowOptions mOptions;
    android::base::unique_fd mFd;
};

void SnapShotCowFuzzer::fillOptions() {
    mOptions.cluster_ops = mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxOpsSize);
    mOptions.max_blocks = mFdp.ConsumeIntegralInRange<uint64_t>(kMinSize, kMaxOpsSize);
    int32_t block = mFdp.ConsumeIntegralInRange<uint32_t>(kMinBlockSize, kMaxOpsSize);
    if (block % 2 == 0) {
        ++block;
    }
    mOptions.block_size = block;
    mOptions.batch_write = mFdp.ConsumeBool();
    mOptions.scratch_space = mFdp.ConsumeBool();
    if (mFdp.ConsumeBool()) {
        mOptions.compression = mFdp.PickValueInArray<std::string>(kCompressionMethods);
    } else {
        mOptions.compression = mFdp.ConsumeRandomLengthString(kStringLength);
    }
    mOptions.num_compress_threads = mFdp.ConsumeIntegralInRange<uint32_t>(kMinThread, kMaxThread);
    mOptions.num_merge_ops = mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxOpsSize);
}

bool SnapShotCowFuzzer::initReader() {
    android::snapshot::CowReader::ReaderFlags readerFlag =
            (android::snapshot::CowReader::ReaderFlags)(mFdp.ConsumeBool() ? kDefault
                                                                           : kUserspaceMerge);

    mFd.reset(dup(mCow->fd));
    mCowReader = std::make_unique<CowReader>(readerFlag, mFdp.ConsumeBool());

    bool status;
    if (mFdp.ConsumeBool()) {
        status = mCowReader->Parse(
                mCow->fd, mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize) /* label*/);
    } else {
        status = mCowReader->Parse(mCow->fd);
    }
    return status;
}

bool SnapShotCowFuzzer::initWriter() {
    mCow = std::make_unique<TemporaryFile>();
    mFd.reset(dup(mCow->fd));
    fillOptions();
    mCowWriter = std::make_unique<CowWriterV2>(mOptions, std::move(mFd));

    bool status;
    if (mFdp.ConsumeBool()) {
        status = mCowWriter->Initialize();
    } else {
        status = mCowWriter->Initialize(
                mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize) /* label*/);
    }
    return status;
}

void SnapShotCowFuzzer::invokeRead() {
    bool parseStatus = initReader();

    if (mCowReader == nullptr || !parseStatus) {
        return;
    }

    while (mFdp.remaining_bytes()) {
        auto invokeReadAPI = mFdp.PickValueInArray<const std::function<void()>>({

                [&]() { mCowReader->InitForMerge(std::move(mFd)); },
                [&]() {
                    auto cowOpIter = mCowReader->GetOpIter();
                    if (cowOpIter == nullptr) {
                        return;
                    }
                    if (cowOpIter->AtEnd()) {
                        return;
                    }
                    auto op = cowOpIter->Get();
                    const CowHeader& header = mCowReader->GetHeader();
                    size_t ignoreBytes =
                            mFdp.ConsumeIntegralInRange<size_t>(kMinSize, op->data_length);
                    size_t bufferSize = op->data_length - ignoreBytes;
                    std::string buffer(bufferSize, kNullChar);

                    if (bufferSize + ignoreBytes > header.block_size) {
                        return;
                    }

                    mCowReader->ReadData(op, buffer.data(), buffer.size(), ignoreBytes);
                },
                [&]() { mCowReader->VerifyMergeOps(); },
                [&]() { mCowReader->GetRevMergeOpIter(); },
        });

        invokeReadAPI();
    }
}

void SnapShotCowFuzzer::invokeWrite() {
    bool initializeStatus = initWriter();

    if (mCowWriter == nullptr || !initializeStatus) {
        return;
    }

    size_t maxRuns = mFdp.ConsumeIntegralInRange<uint32_t>(kMinStartSize, kMaxSize);
    while (mFdp.remaining_bytes() && --maxRuns && initializeStatus) {
        auto invokeWriteAPI = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    mCowWriter->AddCopy(
                            mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize) /*new_block*/,
                            mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize,
                                                                  kMaxSize) /*old_block*/);
                },
                [&]() {
                    if (!mFinalizedStatus) {
                        mFinalizedStatus = mCowWriter->Finalize();
                    }
                },
                [&]() {
                    if (!mFinalizedStatus) {
                        return;
                    }
                    mFd.reset(dup(mCow->fd));
                    mICowWriter = CreateCowWriter(mFdp.ConsumeIntegralInRange<uint32_t>(
                                                          kMinVersion, kMaxVersion) /*version*/,
                                                  mOptions, std::move(mFd),
                                                  mFdp.ConsumeIntegralInRange<uint64_t>(
                                                          kMinStartSize, kMaxSize) /* label*/);
                },
                [&]() {
                    if (!mFinalizedStatus) {
                        return;
                    }
                    initializeStatus = mCowWriter->Initialize(
                            mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize) /*label*/);
                },
                [&]() {
                    std::string initData = mFdp.ConsumeRandomLengthString(kMaxSize);
                    mCowWriter->AddRawBlocks(mFdp.ConsumeIntegralInRange<uint32_t>(
                                                     kMinStartSize, kMaxSize) /*new_block_start*/,
                                             initData.data() /*data*/, initData.size() /*size*/);
                },
                [&]() {
                    mCowWriter->AddZeroBlocks(mFdp.ConsumeIntegralInRange<uint64_t>(
                                                      kMinStartSize, kMaxSize) /*new_block_start*/,
                                              mFdp.ConsumeIntegralInRange<uint64_t>(
                                                      kMinSize, kMaxSize) /*num_blocks)*/);
                },
                [&]() {
                    mCowWriter->AddLabel(
                            mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize) /*label*/);
                },
                [&]() {
                    std::string initData = mFdp.ConsumeRandomLengthString(kMaxSize);
                    mCowWriter->AddXorBlocks(
                            mFdp.ConsumeIntegralInRange<uint32_t>(kMinStartSize,
                                                                  kMaxSize) /*new_block_start,*/,
                            initData.data() /*data*/, initData.size() /*size*/,
                            mFdp.ConsumeIntegralInRange<uint32_t>(kMinStartSize,
                                                                  kMaxSize) /*old_block*/,
                            mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize) /*offset*/);
                },
                [&]() {
                    std::vector<uint32_t> initData;
                    size_t size = mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize);
                    for (int32_t idx = 0; idx < size; ++idx) {
                        initData.push_back(
                                mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize));
                    }

                    mCowWriter->AddSequenceData(initData.size() /*num_ops*/,
                                                initData.data() /*data*/);
                },
        });
        invokeWriteAPI();
    }

    if (!mFinalizedStatus) {
        mFinalizedStatus = mCowWriter->Finalize();
    }
}

void SnapShotCowFuzzer::process() {
    invokeWrite();
    if (mFinalizedStatus) {
        invokeRead();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    SnapShotCowFuzzer snapShotCow(data, size);
    snapShotCow.process();
    return 0;
}
