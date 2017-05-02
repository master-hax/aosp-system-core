/*
 * Copyright (C) 2007-2014 The Android Open Source Project
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

#include "uevent_handler.h"

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libgen.h>
#include <linux/netlink.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <private/android_filesystem_config.h>
#include <selinux/android.h>
#include <selinux/selinux.h>

#include "ueventd.h"
#include "util.h"

#ifdef _INIT_INIT_H
#error "Do not include init.h in files used by ueventd or watchdogd; it will expose init's globals"
#endif

Permissions::Permissions(const std::string& name, mode_t perm, uid_t uid, gid_t gid)
    : name_(name), perm_(perm), uid_(uid), gid_(gid), prefix_(false), wildcard_(false) {
    // If the first * is the last character, then we'll treat name_ as a prefix
    // Otherwise, if a * is present, then we do a full fnmatch().
    auto wildcard_position = name_.find('*');
    if (wildcard_position == name_.length() - 1) {
        prefix_ = true;
        name_.pop_back();
    } else if (wildcard_position != std::string::npos) {
        wildcard_ = true;
    }
}

bool Permissions::Match(const std::string& path) const {
    if (prefix_) {
        return android::base::StartsWith(path, name_.c_str());
    } else if (wildcard_) {
        return fnmatch(name_.c_str(), path.c_str(), FNM_PATHNAME) == 0;
    } else {
        return path == name_;
    }

    return false;
}

bool SysfsPermissions::MatchWithSubsystem(const std::string& path,
                                          const std::string& subsystem) const {
    std::string path_basename = android::base::Basename(path);
    if (name().find(subsystem) != std::string::npos) {
        if (Match("/sys/class/" + subsystem + "/" + path_basename)) return true;
        if (Match("/sys/bus/" + subsystem + "/devices/" + path_basename)) return true;
    }
    return Match(path);
}

void SysfsPermissions::SetPermissions(const std::string& path) const {
    std::string attribute_file = path + "/" + attribute_;
    LOG(INFO) << "fixup " << attribute_file << " " << uid() << " " << gid() << " " << std::oct
              << perm();
    chown(attribute_file.c_str(), uid(), gid());
    chmod(attribute_file.c_str(), perm());
}

std::string Subsystem::ParseDevPath(uevent* uevent) const {
    std::string devname = devname_source_ == DevnameSource::DEVNAME_UEVENT_DEVNAME
                              ? uevent->device_name
                              : android::base::Basename(uevent->path);

    return dir_name_ + "/" + devname;
}

void UeventHandler::FixupSysPermissions(const std::string& upath, const std::string& subsystem) {
    // upaths omit the "/sys" that paths in this list
    // contain, so we prepend it...
    std::string path = "/sys" + upath;

    for (const auto& s : sysfs_permissions_) {
        if (s.MatchWithSubsystem(path, subsystem)) s.SetPermissions(path);
    }

    if (access(path.c_str(), F_OK) == 0) {
        LOG(VERBOSE) << "restorecon_recursive: " << path;
        restorecon(path.c_str(), SELINUX_ANDROID_RESTORECON_RECURSE);
    }
}

std::tuple<mode_t, uid_t, gid_t> UeventHandler::GetDevicePermissions(
    const std::string& path, const std::vector<std::string>& links) {
    // Search the perms list in reverse so that ueventd.$hardware can override ueventd.rc.
    for (auto it = dev_permissions_.rbegin(); it != dev_permissions_.rend(); ++it) {
        if (it->Match(path) || std::any_of(links.begin(), links.end(),
                                           [it](const auto& link) { return it->Match(link); })) {
            return {it->perm(), it->uid(), it->gid()};
        }
    }
    /* Default if nothing found. */
    return {0600, 0, 0};
}

void UeventHandler::MakeDevice(const std::string& path, int block, int major, int minor,
                               const std::vector<std::string>& links) {
    dev_t dev;
    char* secontext = NULL;

    auto[mode, uid, gid] = GetDevicePermissions(path, links);
    mode |= (block ? S_IFBLK : S_IFCHR);

    if (sehandle_) {
        std::vector<const char*> c_links;
        for (const auto& link : links) {
            c_links.emplace_back(link.c_str());
        }
        c_links.emplace_back(nullptr);
        if (selabel_lookup_best_match(sehandle_, &secontext, path.c_str(), &c_links[0], mode)) {
            PLOG(ERROR) << "Device '" << path << "' not created; cannot find SELinux label";
            return;
        }
        setfscreatecon(secontext);
    }

    dev = makedev(major, minor);
    /* Temporarily change egid to avoid race condition setting the gid of the
     * device node. Unforunately changing the euid would prevent creation of
     * some device nodes, so the uid has to be set with chown() and is still
     * racy. Fixing the gid race at least fixed the issue with system_server
     * opening dynamic input devices under the AID_INPUT gid. */
    if (setegid(gid)) {
        PLOG(ERROR) << "setegid(" << gid << ") for " << path << " device failed";
        goto out;
    }
    /* If the node already exists update its SELinux label to handle cases when
     * it was created with the wrong context during coldboot procedure. */
    if (mknod(path.c_str(), mode, dev) && (errno == EEXIST) && secontext) {
        char* fcon = nullptr;
        int rc = lgetfilecon(path.c_str(), &fcon);
        if (rc < 0) {
            PLOG(ERROR) << "Cannot get SELinux label on '" << path << "' device";
            goto out;
        }

        bool different = strcmp(fcon, secontext) != 0;
        freecon(fcon);

        if (different && lsetfilecon(path.c_str(), secontext)) {
            PLOG(ERROR) << "Cannot set '" << secontext << "' SELinux label on '" << path
                        << "' device";
        }
    }

out:
    chown(path.c_str(), uid, -1);
    if (setegid(AID_ROOT)) {
        PLOG(FATAL) << "setegid(AID_ROOT) failed";
    }

    if (secontext) {
        freecon(secontext);
        setfscreatecon(NULL);
    }
}

void PlatformDeviceList::Add(const std::string& path) {
    platform_devices_.emplace_back(path);
}

void PlatformDeviceList::Remove(const std::string& path) {
    auto it = std::find(platform_devices_.begin(), platform_devices_.end(), path);
    if (it != platform_devices_.end()) platform_devices_.erase(it);
}

// Given a path that may start with a platform device, find the length of the
// platform device prefix.  If it doesn't start with a platform device, return false
bool PlatformDeviceList::Find(const std::string& path, std::string* out_path) const {
    out_path->clear();
    // platform_devices is searched backwards, since parents are added before their children,
    // and we want to match as deep of a child as we can.
    for (auto it = platform_devices_.rbegin(); it != platform_devices_.rend(); ++it) {
        auto platform_device_path_length = it->length();
        if (platform_device_path_length < path.length() &&
            path[platform_device_path_length] == '/' &&
            android::base::StartsWith(path, it->c_str())) {
            *out_path = *it;
            return true;
        }
    }
    return false;
}

/* Given a path that may start with a PCI device, populate the supplied buffer
 * with the PCI domain/bus number and the peripheral ID and return 0.
 * If it doesn't start with a PCI device, or there is some error, return -1 */
static bool find_pci_device_prefix(const std::string& path, std::string* result) {
    result->clear();

    if (!android::base::StartsWith(path, "/devices/pci")) return false;

    /* Beginning of the prefix is the initial "pci" after "/devices/" */
    std::string::size_type start = 9;

    /* End of the prefix is two path '/' later, capturing the domain/bus number
     * and the peripheral ID. Example: pci0000:00/0000:00:1f.2 */
    auto end = path.find('/', start);
    if (end == std::string::npos) return false;

    end = path.find('/', end + 1);
    if (end == std::string::npos) return false;

    auto length = end - start;
    if (length <= 4) {
        // The minimum string that will get to this check is 'pci/', which is malformed,
        // so return false
        return false;
    }

    *result = path.substr(start, length);
    return true;
}

/* Given a path that may start with a virtual block device, populate
 * the supplied buffer with the virtual block device ID and return 0.
 * If it doesn't start with a virtual block device, or there is some
 * error, return -1 */
static bool find_vbd_device_prefix(const std::string& path, std::string* result) {
    result->clear();

    if (!android::base::StartsWith(path, "/devices/vbd-")) return false;

    /* Beginning of the prefix is the initial "vbd-" after "/devices/" */
    std::string::size_type start = 13;

    /* End of the prefix is one path '/' later, capturing the
       virtual block device ID. Example: 768 */
    auto end = path.find('/', start);
    if (end == std::string::npos) return false;

    auto length = end - start;
    if (length == 0) return false;

    *result = path.substr(start, length);
    return true;
}

std::vector<std::string> UeventHandler::GetCharacterDeviceSymlinks(uevent* uevent) const {
    std::string parent_device;
    if (!platform_devices_.Find(uevent->path, &parent_device)) return {};

    // skip path to the parent driver
    std::string path = uevent->path.substr(parent_device.length());

    if (!android::base::StartsWith(path, "/usb")) return {};

    // skip root hub name and device. use device interface
    // skip 3 slashes, including the first / by starting the search at the 1st character, not 0th.
    // then extract what comes between the 3rd and 4th slash
    // e.g. "/usb/usb_device/name/tty2-1:1.0" -> "name"

    std::string::size_type start = 0;
    start = path.find('/', start + 1);
    if (start == std::string::npos) return {};

    start = path.find('/', start + 1);
    if (start == std::string::npos) return {};

    auto end = path.find('/', start + 1);
    if (end == std::string::npos) return {};

    start++;  // Skip the first '/'

    auto length = end - start;
    if (length == 0) return {};

    auto name_string = path.substr(start, length);

    std::vector<std::string> links;
    links.emplace_back("/dev/usb/" + uevent->subsystem + name_string);

    mkdir("/dev/usb", 0755);

    return links;
}

// replaces any unacceptable characters with '_', the
// length of the resulting string is equal to the input string
void sanitize_partition_name(std::string* string) {
    const char* accept =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "_-.";

    if (!string) return;

    std::string::size_type pos = 0;
    while ((pos = string->find_first_not_of(accept, pos)) != std::string::npos) {
        (*string)[pos] = '_';
    }
}

std::vector<std::string> UeventHandler::GetBlockDeviceSymlinks(uevent* uevent) const {
    std::string device;
    std::string type;

    if (platform_devices_.Find(uevent->path, &device)) {
        // Skip /devices/platform or /devices/ if present
        static const std::string devices_platform_prefix = "/devices/platform/";
        static const std::string devices_prefix = "/devices/";

        if (android::base::StartsWith(device, devices_platform_prefix.c_str())) {
            device = device.substr(devices_platform_prefix.length());
        } else if (android::base::StartsWith(device, devices_prefix.c_str())) {
            device = device.substr(devices_prefix.length());
        }

        type = "platform";
    } else if (find_pci_device_prefix(uevent->path, &device)) {
        type = "pci";
    } else if (find_vbd_device_prefix(uevent->path, &device)) {
        type = "vbd";
    } else {
        return {};
    }

    std::vector<std::string> links;

    LOG(VERBOSE) << "found " << type << " device " << device;

    auto link_path = "/dev/block/" + type + "/" + device;

    if (!uevent->partition_name.empty()) {
        std::string partition_name_sanitized(uevent->partition_name);
        sanitize_partition_name(&partition_name_sanitized);
        if (partition_name_sanitized != uevent->partition_name) {
            LOG(VERBOSE) << "Linking partition '" << uevent->partition_name << "' as '"
                         << partition_name_sanitized << "'";
        }
        links.emplace_back(link_path + "/by-name/" + partition_name_sanitized);
    }

    if (uevent->partition_num >= 0) {
        links.emplace_back(link_path + "/by-num/p" + std::to_string(uevent->partition_num));
    }

    auto last_slash = uevent->path.rfind('/');
    links.emplace_back(link_path + "/" + uevent->path.substr(last_slash + 1));

    return links;
}

void UeventHandler::HandleDevice(const std::string& action, const std::string& devpath, int block,
                                 int major, int minor, const std::vector<std::string>& links) {
    if (action == "add") {
        MakeDevice(devpath, block, major, minor, links);
        for (const auto& link : links) {
            if (mkdir_recursive(android::base::Dirname(link), 0755, sehandle_)) {
                PLOG(ERROR) << "Failed to create directory " << android::base::Dirname(link);
            }

            if (symlink(devpath.c_str(), link.c_str()) && errno != EEXIST) {
                PLOG(ERROR) << "Failed to symlink " << devpath << " to " << link;
            }
        }
    }

    if (action == "remove") {
        for (const auto& link : links) {
            std::string link_path;
            if (android::base::Readlink(link, &link_path) && link_path == devpath) {
                unlink(link.c_str());
            }
        }
        unlink(devpath.c_str());
    }
}

void UeventHandler::HandlePlatformDeviceEvent(uevent* uevent) {
    if (uevent->action == "add") {
        platform_devices_.Add(uevent->path);
    } else if (uevent->action == "remove") {
        platform_devices_.Remove(uevent->path);
    }
}

void UeventHandler::HandleBlockDeviceEvent(uevent* uevent) {
    // if it's not a /dev device, nothing to do
    if (uevent->major < 0 || uevent->minor < 0) return;

    const char* base = "/dev/block/";
    make_dir(base, 0755, sehandle_);

    std::string name = android::base::Basename(uevent->path);
    std::string devpath = base + name;

    std::vector<std::string> links;
    if (android::base::StartsWith(uevent->path, "/devices")) {
        links = GetBlockDeviceSymlinks(uevent);
    }

    HandleDevice(uevent->action, devpath, 1, uevent->major, uevent->minor, links);
}

void UeventHandler::HandleGenericDeviceEvent(uevent* uevent) {
    // if it's not a /dev device, nothing to do
    if (uevent->major < 0 || uevent->minor < 0) return;

    std::string devpath;

    if (android::base::StartsWith(uevent->subsystem, "usb")) {
        if (uevent->subsystem == "usb") {
            if (!uevent->device_name.empty()) {
                devpath = "/dev/" + uevent->device_name;
            } else {
                // This imitates the file system that would be created
                // if we were using devfs instead.
                // Minors are broken up into groups of 128, starting at "001"
                int bus_id = uevent->minor / 128 + 1;
                int device_id = uevent->minor % 128 + 1;
                devpath = android::base::StringPrintf("/dev/bus/usb/%03d/%03d", bus_id, device_id);
            }
        } else {
            // ignore other USB events
            return;
        }
    } else if (auto subsystem = std::find(subsystems_.begin(), subsystems_.end(), uevent->subsystem);
               subsystem != subsystems_.end()) {
        devpath = subsystem->ParseDevPath(uevent);
    } else {
        devpath = "/dev/" + android::base::Basename(uevent->path);
    }

    mkdir_recursive(android::base::Dirname(devpath), 0755, sehandle_);

    auto links = GetCharacterDeviceSymlinks(uevent);

    HandleDevice(uevent->action, devpath, 0, uevent->major, uevent->minor, links);
}

void UeventHandler::HandleDeviceEvent(uevent* uevent) {
    if (uevent->action == "add" || uevent->action == "change" || uevent->action == "online") {
        FixupSysPermissions(uevent->path, uevent->subsystem);
    }

    if (uevent->subsystem == "block") {
        HandleBlockDeviceEvent(uevent);
    } else if (uevent->subsystem == "platform") {
        HandlePlatformDeviceEvent(uevent);
    } else {
        HandleGenericDeviceEvent(uevent);
    }
}

// Firmware loading is unrelated from the rest of the cold boot

static void load_firmware(uevent* uevent, const std::string& root, int fw_fd, size_t fw_size,
                          int loading_fd, int data_fd) {
    // Start transfer.
    android::base::WriteFully(loading_fd, "1", 1);

    // Copy the firmware.
    int rc = sendfile(data_fd, fw_fd, nullptr, fw_size);
    if (rc == -1) {
        PLOG(ERROR) << "firmware: sendfile failed { '" << root << "', '" << uevent->firmware
                    << "' }";
    }

    // Tell the firmware whether to abort or commit.
    const char* response = (rc != -1) ? "0" : "-1";
    android::base::WriteFully(loading_fd, response, strlen(response));
}

static int is_booting() {
    return access("/dev/.booting", F_OK) == 0;
}

static void process_firmware_event(uevent* uevent) {
    int booting = is_booting();

    LOG(INFO) << "firmware: loading '" << uevent->firmware << "' for '" << uevent->path << "'";

    std::string root = "/sys" + uevent->path;
    std::string loading = root + "/loading";
    std::string data = root + "/data";

    android::base::unique_fd loading_fd(open(loading.c_str(), O_WRONLY | O_CLOEXEC));
    if (loading_fd == -1) {
        PLOG(ERROR) << "couldn't open firmware loading fd for " << uevent->firmware;
        return;
    }

    android::base::unique_fd data_fd(open(data.c_str(), O_WRONLY | O_CLOEXEC));
    if (data_fd == -1) {
        PLOG(ERROR) << "couldn't open firmware data fd for " << uevent->firmware;
        return;
    }

    static const char* firmware_dirs[] = {"/etc/firmware/", "/vendor/firmware/",
                                          "/firmware/image/"};

try_loading_again:
    for (size_t i = 0; i < arraysize(firmware_dirs); i++) {
        std::string file = firmware_dirs[i] + uevent->firmware;
        android::base::unique_fd fw_fd(open(file.c_str(), O_RDONLY | O_CLOEXEC));
        struct stat sb;
        if (fw_fd != -1 && fstat(fw_fd, &sb) != -1) {
            load_firmware(uevent, root, fw_fd, sb.st_size, loading_fd, data_fd);
            return;
        }
    }

    if (booting) {
        // If we're not fully booted, we may be missing
        // filesystems needed for firmware, wait and retry.
        std::this_thread::sleep_for(100ms);
        booting = is_booting();
        goto try_loading_again;
    }

    LOG(ERROR) << "firmware: could not find firmware for " << uevent->firmware;

    // Write "-1" as our response to the kernel's firmware request, since we have nothing for it.
    write(loading_fd, "-1", 2);
}

static void handle_firmware_event(uevent* uevent) {
    if (uevent->subsystem != "firmware" || uevent->action != "add") return;

    // Loading the firmware in a child means we can do that in parallel...
    // (We ignore SIGCHLD rather than wait for our children.)
    pid_t pid = fork();
    if (pid == 0) {
        Timer t;
        process_firmware_event(uevent);
        LOG(INFO) << "loading " << uevent->path << " took " << t;
        _exit(EXIT_SUCCESS);
    } else if (pid == -1) {
        PLOG(ERROR) << "could not fork to process firmware event for " << uevent->firmware;
    }
}

void UeventHandler::HandleUevent(uevent* uevent) {
    HandleDeviceEvent(uevent);
    handle_firmware_event(uevent);
}

UeventHandler::UeventHandler(std::vector<Permissions> dev_permissions,
                             std::vector<SysfsPermissions> sysfs_permissions,
                             std::vector<Subsystem> subsystems)
    : dev_permissions_(std::move(dev_permissions)),
      sysfs_permissions_(std::move(sysfs_permissions)),
      subsystems_(std::move(subsystems)),
      sehandle_(selinux_android_file_context_handle()) {}

UeventHandler::UeventHandler()
    : UeventHandler(std::vector<Permissions>{}, std::vector<SysfsPermissions>{},
                    std::vector<Subsystem>{}) {}

UeventHandler::~UeventHandler() {}
