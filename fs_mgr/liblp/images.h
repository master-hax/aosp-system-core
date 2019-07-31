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

#include <stdint.h>
#include <map>
#include <memory>
#include <string>

#include <android-base/unique_fd.h>
#include <libavb/libavb.h>
#include <liblp/liblp.h>
#include <libvbmeta/builder.h>
#include <libvbmeta/super_avb_footer_format.h>
#include <sparse/sparse.h>

namespace android {
namespace fs_mgr {

// Helper function to serialize geometry and metadata to a normal file, for
// flashing or debugging.
std::unique_ptr<LpMetadata> ReadFromImageFile(int fd);
bool WriteToImageFile(const char* file, const LpMetadata& metadata);
bool WriteToImageFile(int fd, const LpMetadata& metadata);

// We use an object to build the image file since it requires that data
// pointers be held alive until the sparse file is destroyed. It's easier
// to do this when the data pointers are all in one place.
class ImageBuilder {
  public:
    ImageBuilder(const LpMetadata& metadata, uint32_t block_size,
                 const std::map<std::string, std::string>& images, bool sparsify);

    bool Build();
    bool Export(const std::string& file);
    bool ExportFiles(const std::string& dir);
    bool IsValid() const;

    bool TestFooter(const std::string &file);
    bool WriteSuperAVBFooter();

    using SparsePtr = std::unique_ptr<sparse_file, decltype(&sparse_file_destroy)>;
    const std::vector<SparsePtr>& device_images() const { return device_images_; }

  private:
    bool AddData(sparse_file* file, const std::string& blob, uint64_t sector);
    bool AddPartitionImage(const LpMetadataPartition& partition, const std::string& file);
    int OpenImageFile(const std::string& file);
    bool SectorToBlock(uint64_t sector, uint32_t* block);
    uint64_t BlockToSector(uint64_t block) const;
    bool CheckExtentOrdering();
    uint64_t ComputePartitionSize(const LpMetadataPartition& partition) const;

    std::unique_ptr<AvbFooter> GetPartitionAVBFooter(const int &fd,
                                                     const uint64_t &offset);
    uint64_t GetPhysicalAddress(const LpMetadataPartition &partition,
                                const uint64_t offset);
    std::unique_ptr<SuperAVBFooter> GetSuperAVBFooter();
    std::unique_ptr<SuperFooter> GetSuperFooter(uint64_t super_avb_footer_size);
    bool WriteFooter(const std::string &blob);

    const LpMetadata& metadata_;
    const LpMetadataGeometry& geometry_;
    uint32_t block_size_;
    bool sparsify_;
    SuperAVBFooterBuilder super_avb_footer_builder_;

    std::vector<SparsePtr> device_images_;
    std::string all_metadata_;
    std::string serial_footer_;
    std::map<std::string, std::string> images_;
    std::vector<android::base::unique_fd> temp_fds_;
};

}  // namespace fs_mgr
}  // namespace android
