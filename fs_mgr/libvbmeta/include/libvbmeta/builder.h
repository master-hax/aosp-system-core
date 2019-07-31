#ifndef AVB_FOOTER_BUILDER_H
#define AVB_FOOTER_BUILDER_H

#include <map>
#include <sparse/sparse.h>

#include "super_avb_footer_format.h"
#include "super_footer_format.h"

namespace android {
namespace fs_mgr {

std::string SerializeSuperAVBFooter(const SuperAVBFooter &input);
std::string SerializeSuperFooter(const SuperFooter &input);

class SuperAVBFooterBuilder {
public:
  SuperAVBFooterBuilder();
  bool Init(const std::string partition_name, uint64_t vbmeta_offset,
            uint64_t vbmeta_size);
  std::unique_ptr<SuperAVBFooter> Export();

private:
  std::map<std::string, std::pair<uint64_t, uint64_t>> vbmetas_;
};

class SuperFooterBuilder {
public:
  SuperFooterBuilder(uint64_t offset);
  std::unique_ptr<SuperFooter> Export();

private:
  uint64_t avbfooter_offset_;
};

} // namespace fs_mgr
} // namespace android

#endif /* LIBLP_METADATA_BUILDER_H */