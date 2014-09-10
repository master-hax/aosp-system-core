/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "nativebridge/native_bridge.h"

#include <cstring>
#include <cutils/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>


namespace android {

// Environment values required by the apps running with native bridge.
struct NativeBridgeRuntimeValues {
    const char* cpu_abi;
    const char* cpu_abi2;
    const char* os_arch;
};

// The symbol name exposed by native-bridge with the type of NativeBridgeCallbacks.
static constexpr const char* kNativeBridgeInterfaceSymbol = "NativeBridgeItf";

enum class NativeBridgeState {
  kNotSetup,                        // Initial state.
  kOpened,                          // After successful dlopen.
  kInitialized,                     // After successful initialization.
  kClosed                           // Closed or errors.
};

static const char* kNotSetupString = "kNotSetup";
static const char* kOpenedString = "kOpened";
static const char* kInitializedString = "kInitialized";
static const char* kClosedString = "kClosed";

static const char* GetNativeBridgeStateString(NativeBridgeState state) {
  switch (state) {
    case NativeBridgeState::kNotSetup:
      return kNotSetupString;

    case NativeBridgeState::kOpened:
      return kOpenedString;

    case NativeBridgeState::kInitialized:
      return kInitializedString;

    case NativeBridgeState::kClosed:
      return kClosedString;
  }
}

// Current state of the native bridge.
static NativeBridgeState state = NativeBridgeState::kNotSetup;

// Whether we had an error at some point.
static bool had_error = false;

// Handle of the loaded library.
static void* native_bridge_handle = nullptr;
// Pointer to the callbacks. Available as soon as LoadNativeBridge succeeds, but only initialized
// later.
static NativeBridgeCallbacks* callbacks = nullptr;
// Callbacks provided by the environment to the bridge. Passed to LoadNativeBridge.
static const NativeBridgeRuntimeCallbacks* runtime_callbacks = nullptr;

// The private app directory.
static char* private_dir = nullptr;
// The app instruction set.
static char* instruction_set = nullptr;

static const char* kCpuinfo = "cpuinfo";

// Characters allowed in a native bridge filename. The first character must
// be in [a-zA-Z] (expected 'l' for "libx"). The rest must be in [a-zA-Z0-9._-].
static bool CharacterAllowed(char c, bool first) {
  if (first) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
  } else {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
           (c == '.') || (c == '_') || (c == '-');
  }
}

// We only allow simple names for the library. It is supposed to be a file in
// /system/lib or /vendor/lib. Only allow a small range of characters, that is
// names consisting of [a-zA-Z0-9._-] and starting with [a-zA-Z].
bool NativeBridgeNameAcceptable(const char* nb_library_filename) {
  const char* ptr = nb_library_filename;
  if (*ptr == 0) {
    // Emptry string. Allowed, means no native bridge.
    return true;
  } else {
    // First character must be [a-zA-Z].
    if (!CharacterAllowed(*ptr, true))  {
      // Found an invalid fist character, don't accept.
      ALOGE("Native bridge library %s has been rejected for first character %c", nb_library_filename, *ptr);
      return false;
    } else {
      // For the rest, be more liberal.
      ptr++;
      while (*ptr != 0) {
        if (!CharacterAllowed(*ptr, false)) {
          // Found an invalid character, don't accept.
          ALOGE("Native bridge library %s has been rejected for %c", nb_library_filename, *ptr);
          return false;
        }
        ptr++;
      }
    }
    return true;
  }
}

bool LoadNativeBridge(const char* nb_library_filename,
                      const NativeBridgeRuntimeCallbacks* runtime_cbs) {
  // We expect only one place that calls LoadNativeBridge: Runtime::Init. At that point we are not
  // multi-threaded, so we do not need locking here.

  if (state != NativeBridgeState::kNotSetup) {
    // Setup has been called before. Ignore this call.
    if (nb_library_filename != nullptr) {  // Avoids some log-spam for dalvikvm.
      ALOGW("Called LoadNativeBridge for an already set up native bridge. State is %s.",
            GetNativeBridgeStateString(state));
    }
    // Note: counts as an error, even though the bridge may be functional.
    had_error = true;
    return false;
  }

  if (nb_library_filename == nullptr || *nb_library_filename == 0) {
    state = NativeBridgeState::kClosed;
    return true;
  } else {
    if (!NativeBridgeNameAcceptable(nb_library_filename)) {
      state = NativeBridgeState::kClosed;
      had_error = true;
    } else {
      // Try to open the library.
      void* handle = dlopen(nb_library_filename, RTLD_LAZY);
      if (handle != nullptr) {
        callbacks = reinterpret_cast<NativeBridgeCallbacks*>(dlsym(handle,
                                                                   kNativeBridgeInterfaceSymbol));
        if (callbacks != nullptr) {
          // Store the handle for later.
          native_bridge_handle = handle;
        } else {
          dlclose(handle);
        }
      }

      // Two failure conditions: could not find library (dlopen failed), or could not find native
      // bridge interface (dlsym failed). Both are an error and close the native bridge.
      if (callbacks == nullptr) {
        had_error = true;
        state = NativeBridgeState::kClosed;
      } else {
        runtime_callbacks = runtime_cbs;
        state = NativeBridgeState::kOpened;
      }
    }
    return state == NativeBridgeState::kOpened;
  }
}

void EarlyInitializeNativeBridge(const char* priv_dir, bool has_mount_namespace) {
  if (private_dir != nullptr) {
    size_t len = strlen(private_dir);
    // Make a copy for us.
    priv_dir = new char[len];
    strncpy(private_dir, priv_dir, len);

    // If we do not have a mount namespace, try to create one.
    if (!has_mount_namespace) {
      // Need to create our mount namespace.
      if (unshare(CLONE_NEWNS) != -1) {
        has_mount_namespace = true;
      } else {
        ALOGW("Failed to unshare(): %d", errno);
      }
    }

    // Only bind-mount /proc/cpuinfo if we have a namespace.
    if (has_mount_namespace && len < 1000) {
      // Make sure the cpuinfo file exists.
      char buffer[1024];
      strncpy(buffer, private_dir, len);
      buffer[len] = '/';
      strncpy(buffer + len + 1, kCpuinfo, strlen(kCpuinfo));

      // Open RD | CREATE to make sure it exists, but leave existing file untouched.
      mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
      int fd = open(buffer, O_RDONLY | O_CREAT, mode);
      if (fd != -1) {
        close(fd);
        if (TEMP_FAILURE_RETRY(mount("/proc/cpuinfo", buffer, nullptr, MS_BIND, nullptr)) == -1) {
          ALOGW("Failed to bind-mount %s as /proc/cpuinfo: %d", buffer, errno);
        }
      } else {
        ALOGW("Could not create/open cpuinfo: %d", errno);
      }
    }
  }
}

// Set up the environment for the bridged app.
static void SetupEnvironment(NativeBridgeCallbacks* callbacks, JNIEnv* env, const char* isa) {
  // Need a JNIEnv* to do anything.
  if (env == nullptr) {
    return;
  }

  // Query the bridge for environment values.
  const struct NativeBridgeRuntimeValues* env_values = callbacks->getAppEnv(isa);
  if (env_values == nullptr) {
    return;
  }

  // Keep the JNIEnv clean.
  jint success = env->PushLocalFrame(16);  // That should be small and large enough.
  if (success < 0) {
    // Out of memory, really borked.
    env->ExceptionClear();
    return;
  }

  // Reset CPU_ABI & CPU_ABI2 to values required by the apps running with native bridge.
  if (env_values->cpu_abi != nullptr || env_values->cpu_abi2 != nullptr) {
    jclass bclass_id = env->FindClass("android/os/Build");
    if (bclass_id != nullptr) {
      if (env_values->cpu_abi != nullptr) {
        jfieldID cpu_abi_id = env->GetStaticFieldID(bclass_id, "CPU_ABI", "Ljava/lang/String;");
        if (cpu_abi_id != nullptr) {
          env->SetStaticObjectField(bclass_id, cpu_abi_id, env->NewStringUTF(env_values->cpu_abi));
        } else {
          env->ExceptionClear();
          ALOGW("Could not find CPU_ABI field.");
        }
      }
      if (env_values->cpu_abi2 != nullptr) {
        jfieldID cpu_abi2_id = env->GetStaticFieldID(bclass_id, "CPU_ABI2", "Ljava/lang/String;");
        if (cpu_abi2_id != nullptr) {
          env->SetStaticObjectField(bclass_id, cpu_abi2_id,
                                    env->NewStringUTF(env_values->cpu_abi2));
        } else {
          env->ExceptionClear();
          ALOGW("Could not find CPU_ABI2 field.");
        }
      }
    } else {
      // For example in a host test environment.
      env->ExceptionClear();
      ALOGW("Could not find Build class.");
    }
  }

  if (env_values->os_arch != nullptr) {
    jclass sclass_id = env->FindClass("java/lang/System");
    if (sclass_id != nullptr) {
      jmethodID set_prop_id = env->GetStaticMethodID(sclass_id, "setProperty",
          "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
      if (set_prop_id != nullptr) {
        // Reset os.arch to the value reqired by the apps running with native bridge.
        env->CallStaticObjectMethod(sclass_id, set_prop_id, env->NewStringUTF("os.arch"),
            env->NewStringUTF(env_values->os_arch));
      } else {
        env->ExceptionClear();
        ALOGW("Could not find setProperty method.");
      }
    } else {
      env->ExceptionClear();
      ALOGW("Could not find System class.");
    }
  }

  // Make it pristine again.
  env->PopLocalFrame(nullptr);
}

bool InitializeNativeBridge(JNIEnv* env, const char* instruction_set) {
  // We expect only one place that calls InitializeNativeBridge: Runtime::DidForkFromZygote. At that
  // point we are not multi-threaded, so we do not need locking here.

  if (state == NativeBridgeState::kOpened) {
    // Try to initialize.
    if (callbacks->initialize(runtime_callbacks, private_dir, instruction_set)) {
      SetupEnvironment(callbacks, env, instruction_set);
      state = NativeBridgeState::kInitialized;
    } else {
      // Unload the library.
      dlclose(native_bridge_handle);
      had_error = true;
      state = NativeBridgeState::kClosed;
    }
  } else {
    had_error = true;
    state = NativeBridgeState::kClosed;
  }

  return state == NativeBridgeState::kInitialized;
}

void UnloadNativeBridge() {
  // We expect only one place that calls UnloadNativeBridge: Runtime::DidForkFromZygote. At that
  // point we are not multi-threaded, so we do not need locking here.

  switch(state) {
    case NativeBridgeState::kOpened:
    case NativeBridgeState::kInitialized:
      // Unload.
      dlclose(native_bridge_handle);
      break;

    case NativeBridgeState::kNotSetup:
      // Not even set up. Error.
      had_error = true;
      break;

    case NativeBridgeState::kClosed:
      // Ignore.
      break;
  }

  state = NativeBridgeState::kClosed;
}

bool NativeBridgeError() {
  return had_error;
}

bool NativeBridgeAvailable() {
  return state == NativeBridgeState::kOpened || state == NativeBridgeState::kInitialized;
}

bool NativeBridgeInitialized() {
  // Calls of this are supposed to happen in a state where the native bridge is stable, i.e., after
  // Runtime::DidForkFromZygote. In that case we do not need a lock.
  return state == NativeBridgeState::kInitialized;
}

void* NativeBridgeLoadLibrary(const char* libpath, int flag) {
  if (NativeBridgeInitialized()) {
    return callbacks->loadLibrary(libpath, flag);
  }
  return nullptr;
}

void* NativeBridgeGetTrampoline(void* handle, const char* name, const char* shorty,
                                uint32_t len) {
  if (NativeBridgeInitialized()) {
    return callbacks->getTrampoline(handle, name, shorty, len);
  }
  return nullptr;
}

bool NativeBridgeIsSupported(const char* libpath) {
  if (NativeBridgeInitialized()) {
    return callbacks->isSupported(libpath);
  }
  return false;
}

};  // namespace android
