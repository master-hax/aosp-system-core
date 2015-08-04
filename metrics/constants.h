// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_CONSTANTS_H_
#define METRICS_CONSTANTS_H_

namespace metrics {
static const char kMetricsDirectory[] = "/data/misc/metrics/";
static const char kMetricsEventsFilePath[] = "/data/misc/metrics/uma-events";
static const char kMetricsGUIDFilePath[] = "/data/misc/metrics/Sysinfo.GUID";
static const char kMetricsServer[] = "http://clients4.google.com/uma/v2";
static const char kConsentFilePath[] = "/data/misc/metrics/enabled";
}  // namespace metrics

#endif  // METRICS_CONSTANTS_H_
