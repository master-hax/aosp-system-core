#ifndef LIBVBMETA_BUILDER_H
#define LIBVBMETA_BUILDER_H

#include <map>
#include <sparse/sparse.h>
#include <string>

#include "footer_format.h"

namespace android {
namespace fs_mgr {

class SuperAVBFooterBuilder {
public:
  SuperAVBFooterBuilder();
  SuperAVBFooterBuilder(const SuperAVBFooter &footer);
  bool Init(const std::string partition_name, uint64_t vbmeta_offset,
            uint64_t vbmeta_size);
  void Delete(const std::string &partition_name);
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

#endif /* LIBVBMETA_BUILDER_H */