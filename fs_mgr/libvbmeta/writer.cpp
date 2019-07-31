#include <string>

#include "libvbmeta/footer_format.h"

namespace android {
namespace fs_mgr {

std::string SerializeSuperAVBFooter(const SuperAVBFooter &input) {
  uint32_t avbfooter_size = 0;

  std::string avbfooter = "";
  avbfooter.append(reinterpret_cast<const char *>(&input.header),
                   input.header.header_size);
  avbfooter.resize(SUPER_AVB_FOOTER_HEADER_SIZE);
  avbfooter_size += SUPER_AVB_FOOTER_HEADER_SIZE;

  for (const auto &descriptor : input.descriptors) {
    avbfooter.append(reinterpret_cast<const char *>(&descriptor),
                     SUPER_AVB_FOOTER_DESCRIPTOR_SIZE);
    avbfooter.resize(avbfooter_size + SUPER_AVB_FOOTER_DESCRIPTOR_SIZE);
    avbfooter_size += SUPER_AVB_FOOTER_DESCRIPTOR_SIZE;

    avbfooter.append(descriptor.partition_name);
    avbfooter.resize(avbfooter_size + descriptor.partition_name_length);
    avbfooter_size += descriptor.partition_name_length;
  }
  return avbfooter;
}

std::string SerializeSuperFooter(const SuperFooter &input) {
  std::string footer = "";
  footer.append(reinterpret_cast<const char *>(&input), SUPER_FOOTER_SIZE);
  footer.resize(SUPER_FOOTER_SIZE);
  return footer;
}

} // namespace fs_mgr
} // namespace android