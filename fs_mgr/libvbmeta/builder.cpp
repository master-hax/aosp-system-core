#include <libvbmeta/builder.h>
#include <libvbmeta/footer_format.h>
#include <libvbmeta/writer.h>
#include <openssl/sha.h>

namespace android {
namespace fs_mgr {

SuperAVBFooterBuilder::SuperAVBFooterBuilder() {}
SuperAVBFooterBuilder::SuperAVBFooterBuilder(const SuperAVBFooter &footer) {
  for (const VBMetaDescriptor &descriptor : footer.descriptors) {
    Init(std::string(descriptor.partition_name), descriptor.vbmeta_offset,
         descriptor.vbmeta_size);
  }
}

bool SuperAVBFooterBuilder::Init(const std::string partition_name,
                                 uint64_t vbmeta_offset, uint64_t vbmeta_size) {
  vbmetas_.emplace(std::make_pair(partition_name,
                                  std::make_pair(vbmeta_offset, vbmeta_size)));
  return true;
}

void SuperAVBFooterBuilder::Delete(const std::string &partition_name) {
  vbmetas_.erase(partition_name);
}

std::unique_ptr<SuperAVBFooter> SuperAVBFooterBuilder::Export() {
  std::unique_ptr<SuperAVBFooter> avbfooter =
      std::make_unique<SuperAVBFooter>();

  uint32_t descriptors_size = 0;

  // descriptors
  for (const auto &vbmeta : vbmetas_) {
    VBMetaDescriptor descriptor;
    descriptor.vbmeta_offset = vbmeta.second.first;
    descriptor.vbmeta_size = vbmeta.second.second;
    descriptor.partition_name_length = vbmeta.first.length();
    descriptor.partition_name =
        (char *)malloc(sizeof(char) * descriptor.partition_name_length);
    strcpy(descriptor.partition_name, vbmeta.first.c_str());
    memset(descriptor.reserved, 0, sizeof(descriptor.reserved));
    avbfooter->descriptors.emplace_back(std::move(descriptor));

    descriptors_size += SUPER_AVB_FOOTER_DESCRIPTOR_SIZE +
                        descriptor.partition_name_length * sizeof(char);
  }

  // header
  avbfooter->header.magic = SUPER_AVB_FOOTER_MAGIC;
  avbfooter->header.major_version = SUPER_AVB_FOOTER_MAJOR_VERSION;
  avbfooter->header.minor_version = SUPER_AVB_FOOTER_MINOR_VERSION;
  avbfooter->header.header_size = SUPER_AVB_FOOTER_HEADER_SIZE;
  avbfooter->header.total_size =
      SUPER_AVB_FOOTER_HEADER_SIZE + descriptors_size;
  memset(avbfooter->header.checksum, 0, sizeof(avbfooter->header.checksum));
  avbfooter->header.descriptors_size = descriptors_size;
  std::string serial = SerializeSuperAVBFooter(*avbfooter);
  ::SHA256(reinterpret_cast<const uint8_t *>(serial.c_str()),
           avbfooter->header.total_size, avbfooter->header.checksum);
  return avbfooter;
}

SuperFooterBuilder::SuperFooterBuilder(uint64_t offset) {
  avbfooter_offset_ = offset;
}

std::unique_ptr<SuperFooter> SuperFooterBuilder::Export() {
  std::unique_ptr<SuperFooter> footer = std::make_unique<SuperFooter>();
  footer->magic = SUPER_FOOTER_MAGIC;
  footer->major_version = SUPER_FOOTER_MAJOR_VERSION;
  footer->minor_version = SUPER_FOOTER_MINOR_VERSION;
  footer->avbfooter_offset = avbfooter_offset_;
  memset(footer->reserved, 0, sizeof(footer->reserved));
  return footer;
}

} // namespace fs_mgr
} // namespace android