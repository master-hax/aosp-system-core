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

#define TRACE_TAG ADB

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "commandline.h"
#include "fastdeploy.h"
#include "fastdeploycallbacks.h"
#include "file_sync_service.h"
#include "sysdeps.h"

#include "adb.h"
#include "adb_auth.h"
#include "adb_client.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"

const long kRequiredAgentVersion = 0x00000001;
const char* kHostAgentJarPath =
    "/media/idries/data/aosp/out/target/product/walleye/system/framework/deployagent.jar";
const char* kHostAgentScriptPath =
    "/media/idries/data/aosp/system/core/adb/fastdeploy/deployagent/deployagent";
const char* kDeviceAgentPath = "/data/local/tmp/";
const char* kHostJarLocation = "/media/idries/data/aosp/out/host/linux-x86/framework";

long get_agent_version() {
    const std::string kAgentVersionCommand = "/data/local/tmp/deployagent version";

    std::vector<unsigned char> versionOutputBuffer;
    std::vector<unsigned char> versionErrorBuffer;
    int statusCode;
    DeployAgentBufferCallback cb(&versionOutputBuffer, &versionErrorBuffer, &statusCode);
    int ret = send_shell_command(kAgentVersionCommand, false, &cb);
    long version = -1;

    if (ret == 0 && statusCode == 0 && versionErrorBuffer.size() > 0) {
        version = strtol((char*)versionErrorBuffer.data(), NULL, 16);
    }

    return version;
}

bool deploy_agent(bool checkTimeStamps) {
    std::vector<const char*> srcs;
    srcs.push_back(kHostAgentJarPath);
    srcs.push_back(kHostAgentScriptPath);

    return do_sync_push(srcs, kDeviceAgentPath, checkTimeStamps);
}

bool update_agent(FastDeploy_AgentUpdateStrategy agentUpdateStrategy) {
    long agent_version = get_agent_version();

    switch (agentUpdateStrategy) {
        case FastDeploy_AgentUpdateAlways:
            deploy_agent(false);
            break;
        case FastDeploy_AgentUpdateNewerTimeStamp:
            deploy_agent(true);
            break;
        case FastDeploy_AgentUpdateDifferentVersion:
            if (agent_version != kRequiredAgentVersion) {
                if (agent_version < 0) {
                    printf("Could not detect agent on device, deploying\n");
                } else {
                    printf("Device agent version is (%ld), (%ld) is required, re-deploying\n",
                           agent_version, kRequiredAgentVersion);
                }
                deploy_agent(false);
            }
            break;
    }

    agent_version = get_agent_version();
    return (agent_version == kRequiredAgentVersion);
}

static std::string get_packagename_from_apk(const char* apkPath) {
    char streamBuffer[128 * 1024];
    char packageNameBuffer[256];
    std::vector<unsigned char> commandOutput;

    // TODO: remove this grep call!!!
    std::string apkInfoCmd =
        android::base::StringPrintf("aapt dump badging %s | grep package:\\ name", apkPath);
    // TODO: and this...
    FILE* process = popen(apkInfoCmd.c_str(), "r");
    if (process == NULL) {
        return "";
    }

    int bytes_read;
    do {
        bytes_read = fread(streamBuffer, 1, sizeof(streamBuffer), process);
        if (bytes_read > 0) {
            commandOutput.insert(commandOutput.end(), streamBuffer, streamBuffer + bytes_read);
        }
    } while (bytes_read == sizeof(streamBuffer));

    packageNameBuffer[0] = '\0';
    sscanf((char*)commandOutput.data(), "package: name='%256s", packageNameBuffer);
    for (int i = 0; i < (int)strlen(packageNameBuffer); i++) {
        if (packageNameBuffer[i] == '\'') {
            packageNameBuffer[i] = ' ';
        }
    }
    pclose(process);

    std::string packageName = packageNameBuffer;
    packageName.erase(packageName.find_last_not_of(" ") + 1);
    return packageName;
}

int extract_metadata(const char* apkPath, FILE* outputFp) {
    std::string packageName = get_packagename_from_apk(apkPath);
    if (packageName.size() == 0) {
        return -1;
    }

    const std::string kAgentExtractCommandPattern = "/data/local/tmp/deployagent extract %s";
    std::string extractCommand =
        android::base::StringPrintf(kAgentExtractCommandPattern.c_str(), packageName.c_str());

    std::vector<unsigned char> extractErrorBuffer;
    int statusCode;
    DeployAgentFileCallback cb(outputFp, &extractErrorBuffer, &statusCode);
    int ret = send_shell_command(extractCommand.c_str(), false, &cb);

    if (ret == 0) {
        return cb.getBytesWritten();
    }

    return ret;
}

int create_patch(const char* apkPath, const char* metadataPath, const char* patchPath) {
    const char* kGeneratePatchCommandPattern =
        "java -Xbootclasspath/a:%s/host-libprotobuf-java-lite.jar -jar %s/deploypatchgenerator.jar "
        "%s %s > %s";
    std::string generatePatchCommand =
        android::base::StringPrintf(kGeneratePatchCommandPattern, kHostJarLocation,
                                    kHostJarLocation, apkPath, metadataPath, patchPath);
    printf("generate: %s\n", generatePatchCommand.c_str());
    return system(generatePatchCommand.c_str());
}

int install_patch(const char* apkPath, const char* patchPath) {
    const std::string kAgentApplyCommandPattern = "/data/local/tmp/deployagent apply %s %s";

    std::string packageName = get_packagename_from_apk(apkPath);
    if (packageName.size() == 0) {
        return -1;
    }

    std::vector<const char*> srcs;
    std::string patchDevicePath =
        android::base::StringPrintf("%s%s.patch", kDeviceAgentPath, packageName.c_str());
    srcs.push_back(patchPath);
    bool push_ok = do_sync_push(srcs, patchDevicePath.c_str(), false);

    if (push_ok == false) {
        return -1;
    }

    std::vector<unsigned char> applyOutputBuffer;
    std::vector<unsigned char> applyErrorBuffer;
    int statusCode;

    std::string applyPatchCommand = android::base::StringPrintf(
        kAgentApplyCommandPattern.c_str(), packageName.c_str(), patchDevicePath.c_str());
    DeployAgentBufferCallback cb(&applyOutputBuffer, &applyErrorBuffer, &statusCode);
    int ret = send_shell_command(applyPatchCommand, false, &cb);

    if (applyErrorBuffer.size() > 0) {
        printf("%.*s\n", (int)applyErrorBuffer.size(), (char*)applyErrorBuffer.data());
    }

    if (ret != 0) {
        return ret;
    }

    return statusCode;
}
