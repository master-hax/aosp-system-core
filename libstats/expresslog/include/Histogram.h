//
// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#pragma once
#include <stdint.h>

#include <memory>

namespace android {
namespace expresslog {

static constexpr int kInvalidBinIndex = -1;

/** Histogram encapsulates StatsD write API calls */
class Histogram final {
public:
    class BinOptions {
    public:
        virtual ~BinOptions() = default;
        /**
         * Returns bins count to be used by a Histogram
         *
         * @return bins count used to initialize Options, including overflow & underflow bins
         * @hide
         */
        virtual int getBinsCount() const = 0;

        /**
         * @return zero based index
         * Calculates bin index for the input sample value
         * index == 0 stands for underflow
         * index == getBinsCount() - 1 stands for overflow
         * @hide
         */
        virtual int getBinForSample(float sample) const = 0;
    };

    /** Used by Histogram to map data sample to corresponding bin for uniform bins */
    class UniformOptions : public BinOptions {
    public:
        UniformOptions(int binCount, float minValue, float exclusiveMaxValue);

        int getBinsCount() const override {
            return mBinCount;
        }

        int getBinForSample(float sample) const override;

    private:
        int mBinCount;
        float mMinValue;
        float mExclusiveMaxValue;
        float mBinSize;
    };

    Histogram(const char* metricName, std::shared_ptr<BinOptions> binOptions);

    /**
     * Logs increment sample count for automatically calculated bin
     */
    void logSample(float sample);

private:
    const int64_t mMetricIdHash;
    std::shared_ptr<BinOptions> mBinOptions;
};

}  // namespace expresslog
}  // namespace android
