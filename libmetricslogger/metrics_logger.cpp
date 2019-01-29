/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "metricslogger/metrics_logger.h"

#include <cstdlib>

#include <android-base/chrono_utils.h>
#include <log/event_tag_map.h>

using namespace android;

namespace {

const static int kStatsEventTag = 1937006964;
const static int kKeyValuePairAtomId = 83;

// Safe initializer for metricslogger. Ensures android_lookupEventTagNum is only called if
// android_openEventTagMap succeeds. The former dereferences null otherwise.
class MetricsLoggerInitializer final {
  public:
    static const MetricsLoggerInitializer& Instance() {
        static MetricsLoggerInitializer instance;
        return instance;
    }

    inline bool IsEnabled() const { return enabled_; }

    inline int GetSysuiMultiActionTag() const { return sysui_multi_action_tag_; }

  private:
    MetricsLoggerInitializer() {
        EventTagMap* eventTagMap = android_openEventTagMap(nullptr);
        if (eventTagMap != nullptr) {
            sysui_multi_action_tag_ = android_lookupEventTagNum(eventTagMap, "sysui_multi_action",
                                                                "(content|4)", ANDROID_LOG_UNKNOWN);
            enabled_ = true;
        } else {
            sysui_multi_action_tag_ = 0;
            enabled_ = false;
        }
    }

    bool enabled_;
    int sysui_multi_action_tag_;
};

int64_t getElapsedTimeNanoSinceBoot() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   android::base::boot_clock::now().time_since_epoch())
            .count();
}

}  // namespace

namespace android {
namespace metricslogger {

// Mirror com.android.internal.logging.MetricsLogger#histogram().
void LogHistogram(const std::string& event, int32_t data) {
    if (MetricsLoggerInitializer::Instance().IsEnabled()) {
        android_log_event_list log(MetricsLoggerInitializer::Instance().GetSysuiMultiActionTag());
        log << LOGBUILDER_CATEGORY << LOGBUILDER_HISTOGRAM << LOGBUILDER_NAME << event
            << LOGBUILDER_BUCKET << data << LOGBUILDER_VALUE << 1 << LOG_ID_EVENTS;

        stats_event_list stats_log(kStatsEventTag);
        stats_log << getElapsedTimeNanoSinceBoot() << kKeyValuePairAtomId << LOGBUILDER_CATEGORY
                  << LOGBUILDER_HISTOGRAM << LOGBUILDER_NAME << event << LOGBUILDER_BUCKET << data
                  << LOGBUILDER_VALUE << 1;
        stats_log.write(LOG_ID_STATS);
    }
}

// Mirror com.android.internal.logging.MetricsLogger#count().
void LogCounter(const std::string& name, int32_t val) {
    if (MetricsLoggerInitializer::Instance().IsEnabled()) {
        android_log_event_list log(MetricsLoggerInitializer::Instance().GetSysuiMultiActionTag());
        log << LOGBUILDER_CATEGORY << LOGBUILDER_COUNTER << LOGBUILDER_NAME << name
            << LOGBUILDER_VALUE << val << LOG_ID_EVENTS;

        stats_event_list stats_log(kStatsEventTag);
        stats_log << getElapsedTimeNanoSinceBoot() << kKeyValuePairAtomId << LOGBUILDER_CATEGORY
                  << LOGBUILDER_COUNTER << LOGBUILDER_NAME << name << LOGBUILDER_VALUE << val;
        stats_log.write(LOG_ID_STATS);
    }
}

// Mirror com.android.internal.logging.MetricsLogger#action().
void LogMultiAction(int32_t category, int32_t field, const std::string& value) {
    if (MetricsLoggerInitializer::Instance().IsEnabled()) {
        android_log_event_list log(MetricsLoggerInitializer::Instance().GetSysuiMultiActionTag());
        log << LOGBUILDER_CATEGORY << category << LOGBUILDER_TYPE << TYPE_ACTION << field << value
            << LOG_ID_EVENTS;

        stats_event_list stats_log(kStatsEventTag);
        stats_log << getElapsedTimeNanoSinceBoot() << kKeyValuePairAtomId << LOGBUILDER_CATEGORY
                  << category << LOGBUILDER_TYPE << TYPE_ACTION << field << value;
        stats_log.write(LOG_ID_STATS);
    }
}

ComplexEventLogger::ComplexEventLogger(int category)
    : logger(MetricsLoggerInitializer::Instance().GetSysuiMultiActionTag()),
      stats_logger(kStatsEventTag) {
    if (MetricsLoggerInitializer::Instance().IsEnabled()) {
        logger << LOGBUILDER_CATEGORY << category;
        stats_logger << getElapsedTimeNanoSinceBoot() << kKeyValuePairAtomId << LOGBUILDER_CATEGORY
                     << category;
    }
}

void ComplexEventLogger::SetPackageName(const std::string& package_name) {
    if (MetricsLoggerInitializer::Instance().IsEnabled()) {
        logger << LOGBUILDER_PACKAGENAME << package_name;
        stats_logger << LOGBUILDER_PACKAGENAME << package_name;
    }
}

void ComplexEventLogger::AddTaggedData(int tag, int32_t value) {
    if (MetricsLoggerInitializer::Instance().IsEnabled()) {
        logger << tag << value;
        stats_logger << tag << value;
    }
}

void ComplexEventLogger::AddTaggedData(int tag, const std::string& value) {
    if (MetricsLoggerInitializer::Instance().IsEnabled()) {
        logger << tag << value;
        stats_logger << tag << value;
    }
}

void ComplexEventLogger::AddTaggedData(int tag, int64_t value) {
    if (MetricsLoggerInitializer::Instance().IsEnabled()) {
        logger << tag << value;
        stats_logger << tag << value;
    }
}

void ComplexEventLogger::AddTaggedData(int tag, float value) {
    if (MetricsLoggerInitializer::Instance().IsEnabled()) {
        logger << tag << value;
        stats_logger << tag << value;
    }
}

void ComplexEventLogger::Record() {
    if (MetricsLoggerInitializer::Instance().IsEnabled()) {
        logger << LOG_ID_EVENTS;
        stats_logger.write(LOG_ID_STATS);
    }
}

}  // namespace metricslogger
}  // namespace android
