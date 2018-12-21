/*
 *  Copyright 2014 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#pragma once

#include <sys/cdefs.h>
#include <sys/types.h>
#include <string>
#include <vector>

__BEGIN_DECLS

// stune profiles
static const std::string TP_HighEnergySaving = "HighEnergySaving";
static const std::string TP_NormalPerformance = "NormalPerformance";
static const std::string TP_HighPerformance = "HighPerformance";
static const std::string TP_MaxPerformance = "MaxPerformance";
static const std::string TP_RealtimePerformance = "RealtimePerformance";

static const std::string TP_CpuPolicySpread = "CpuPolicySpread";
static const std::string TP_CpuPolicyPack = "CpuPolicyPack";

// cpuset profiles
static const std::string TP_VrKernelCapacity = "VrKernelCapacity";
static const std::string TP_VrServiceCapacityLow = "VrServiceCapacityLow";
static const std::string TP_VrServiceCapacityNormal = "VrServiceCapacityNormal";
static const std::string TP_VrServiceCapacityHigh = "VrServiceCapacityHigh";

static const std::string TP_VrProcessCapacityLow = "VrProcessCapacityLow";
static const std::string TP_VrProcessCapacityNormal = "VrProcessCapacityNormal";
static const std::string TP_VrProcessCapacityHigh = "VrProcessCapacityHigh";

static const std::string TP_ProcessCapacityLow = "ProcessCapacityLow";
static const std::string TP_ProcessCapacityNormal = "ProcessCapacityNormal";
static const std::string TP_ProcessCapacityHigh = "ProcessCapacityHigh";
static const std::string TP_ProcessCapacityMax = "ProcessCapacityMax";

static const std::string TP_ServiceCapacityLow = "ServiceCapacityLow";
static const std::string TP_ServiceCapacityRestricted = "ServiceCapacityRestricted";

static const std::string TP_CameraServiceCapacity = "CameraServiceCapacity";

// timer slack profiles
static const std::string TP_TimerSlackHigh = "TimerSlackHigh";
static const std::string TP_TimerSlackNormal = "TimerSlackNormal";

// attribute names
static const std::string TPA_LowCapacityCPUs = "LowCapacityCPUs";
static const std::string TPA_HighCapacityCPUs = "HighCapacityCPUs";
static const std::string TPA_MaxCapacityCPUs = "MaxCapacityCPUs";

static const std::string TPA_CgroupV2Root = "CgroupV2Root";

bool IsCgroupFileSystem(const std::string& system);
bool CgroupDetect();

bool CgroupGetControllerPath(const std::string& cgroup_name, std::string* path);
bool CgroupGetAttributePath(const std::string& attr_name, std::string* path);
bool CgroupGetAttributePathForTask(const std::string& attr_name, int tid, std::string* path);

bool UsePerAppMemcg();

int SetTaskProfiles(int tid, const std::vector<std::string>& profiles);
int SetProcessProfiles(uid_t uid, pid_t pid, const std::vector<std::string>& profiles);

// Return 0 and removes the cgroup if there are no longer any processes in it.
// Returns -1 in the case of an error occurring or if there are processes still running
// even after retrying for up to 200ms.
int killProcessGroup(uid_t uid, int initialPid, int signal);

// Returns the same as killProcessGroup(), however it does not retry, which means
// that it only returns 0 in the case that the cgroup exists and it contains no processes.
int killProcessGroupOnce(uid_t uid, int initialPid, int signal);

int createProcessGroup(uid_t uid, int initialPid, bool memControl = false);

// Set various properties of a process group. For these functions to work, the process group must
// have been created by passing memControl=true to createProcessGroup.
bool setProcessGroupSwappiness(uid_t uid, int initialPid, int swappiness);
bool setProcessGroupSoftLimit(uid_t uid, int initialPid, int64_t softLimitInBytes);
bool setProcessGroupLimit(uid_t uid, int initialPid, int64_t limitInBytes);

void removeAllProcessGroups(void);

__END_DECLS
