// Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <functional>
#include <string>

#include <android-base/macros.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>
#include <liblp/builder.h>
#include <libsnapshot/snapshot.h>
#include <update_engine/update_metadata.pb.h>

namespace android {
namespace snapshot {

struct AutoDevice {
    virtual ~AutoDevice(){};
    void Release();

  protected:
    AutoDevice(const std::string& name) : name_(name) {}
    std::string name_;

  private:
    DISALLOW_COPY_AND_ASSIGN(AutoDevice);
    AutoDevice(AutoDevice&& other) = delete;
};

// A list of devices we created along the way.
// - Whenever a device is created that is subject to GC'ed at the end of
//   this function, add it to this list.
// - If any error has occurred, the list is destroyed, and all these devices
//   are cleaned up.
// - Upon success, Release() should be called so that the created devices
//   are kept.
struct AutoDeviceList {
    ~AutoDeviceList();
    template <typename T, typename... Args>
    void EmplaceBack(Args&&... args) {
        devices_.emplace_back(std::make_unique<T>(std::forward<Args>(args)...));
    }
    void Release();

  private:
    std::vector<std::unique_ptr<AutoDevice>> devices_;
};

// Automatically unmap a device upon deletion.
struct AutoUnmapDevice : AutoDevice {
    // On destruct, delete |name| from device mapper.
    AutoUnmapDevice(android::dm::DeviceMapper* dm, const std::string& name)
        : AutoDevice(name), dm_(dm) {}
    AutoUnmapDevice(AutoUnmapDevice&& other) = default;
    ~AutoUnmapDevice();

  private:
    DISALLOW_COPY_AND_ASSIGN(AutoUnmapDevice);
    android::dm::DeviceMapper* dm_ = nullptr;
};

// Automatically unmap an image upon deletion.
struct AutoUnmapImage : AutoDevice {
    // On destruct, delete |name| from image manager.
    AutoUnmapImage(android::fiemap::IImageManager* images, const std::string& name)
        : AutoDevice(name), images_(images) {}
    AutoUnmapImage(AutoUnmapImage&& other) = default;
    ~AutoUnmapImage();

  private:
    DISALLOW_COPY_AND_ASSIGN(AutoUnmapImage);
    android::fiemap::IImageManager* images_ = nullptr;
};

// Automatically deletes a snapshot. |name| should be the name of the partition, e.g. "system_a".
// Client is responsible for maintaining the lifetime of |manager| and |lock|.
struct AutoDeleteSnapshot : AutoDevice {
    AutoDeleteSnapshot(SnapshotManager* manager, SnapshotManager::LockedFile* lock,
                       const std::string& name)
        : AutoDevice(name), manager_(manager), lock_(lock) {}
    AutoDeleteSnapshot(AutoDeleteSnapshot&& other);
    ~AutoDeleteSnapshot();

  private:
    DISALLOW_COPY_AND_ASSIGN(AutoDeleteSnapshot);
    SnapshotManager* manager_ = nullptr;
    SnapshotManager::LockedFile* lock_ = nullptr;
};

// Return a list of partitions in |builder| with the name ending in |suffix|.
std::vector<android::fs_mgr::Partition*> ListPartitionsWithSuffix(
        android::fs_mgr::MetadataBuilder* builder, const std::string& suffix);

// Initialize a device before using it as the COW device for a dm-snapshot device.
bool InitializeCow(const std::string& device);

// template<typename T>
// struct NamedPtr {
//   std::string name;
//   T* ptr;

//   operator T*() {
//     return ptr;
//   }

//   T* operator->() {
//     return *ptr;
//   }

//   T* get() {
//     return ptr;
//   }
// };

// template <typename ObjectIterator>
// struct ConstNamedPtrIterator : public std::iterator <
//         std::forward_iterator_tag, /* Category */
//         NamedPtr<typename std::iterator_traits<ObjectIterator>::value_type> /* type */>
// {
//     using traits = std::iterator_traits<ConstNamedPtrIterator>;
//     using value_type = typename traits::value_type;
//     using ptr_type = typename traits::pointer;
//     using ref_type = typename traits::reference;
//     using diff_type = typename traits::difference_type;

//     ConstNamedPtrIterator(ObjectIterator iter, std::string_view suffix) :
//             iter_(iter), suffix_(suffix) {
//     }

//     inline ConstNamedPtrIterator &operator++()    {
//         iter_++;
//         current_ = std::nullopt;
//         return *this;
//     }

//     inline ConstNamedPtrIterator operator++(int) {
//         ConstNamedPtrIterator i = *this;
//         ++(*this);
//         return i;
//     }

//     inline ref_type operator*() const  {
//         if (!current_.has_value()) {
//             current_ = std::make_optional<value_type>(iter_->name() + suffix_, &*iter_);
//         }
//         return current_;
//     }

//     inline ptr_type operator->() const {
//         return &*this;
//     }

//     // For efficiency, do not compare suffix and assume they match.
//     inline bool operator==(const ConstNamedPtrIterator &rhs) const {
//         return iter_ == rhs.iter_;
//     }

//     inline bool operator!=(const ConstNamedPtrIterator &rhs) const {
//         return iter_ != rhs.iter_;
//     }

// private:
//     ObjectIterator iter_;
//     std::string suffix_;
//     std::optional<value_type> current_;
// };

// template <typename Iterator>
// struct Iterable {
//     Iterator begin_iterator;
//     Iterator end_iterator;
//     Iterator begin() const  { return begin_iterator; }
//     Iterator end() const { return end_iterator; }
// };

// void IterateGroups(const chromeos_update_engine::DynamicPartitionMetadata& metadata) {

// }

}  // namespace snapshot
}  // namespace android
