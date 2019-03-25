#define LOG_TAG "nativezygote"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android/dlext.h>
#include <dlfcn.h>

#include <string>
#include <vector>

#include "nativezygote_server.h"

void PreloadLibraries() {
    std::vector<std::string> libraries =
            android::base::Split(android::base::GetProperty("ro.nativezygote.preload", ""), ":");
    for (std::string const& lib : libraries) {
        constexpr android_dlextinfo extinfo = {
                .flags = ANDROID_DLEXT_PRELOAD,
        };
        if (android_dlopen_ext(lib.c_str(), RTLD_LOCAL, &extinfo)) {
            LOG(INFO) << "Preloaded library " << lib;
        } else {
            LOG(ERROR) << "Failed to preload library " << lib;
        }
    }
}

int main() {
    LOG(INFO) << "Native zygote starting";

    const char* socket_name = getenv("NATIVEZYGOTE_SOCKET");
    if (!socket_name) {
        LOG(FATAL) << "Environment variable NATIVEZYGOTE_SOCKET not set";
    }

    PreloadLibraries();

    android::init::NativeZygoteServer server(socket_name);
    server.MainLoop();

    return 0;
}
