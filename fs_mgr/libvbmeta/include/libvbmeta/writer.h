#ifndef LIBVBMETA_WRITER_H
#define LIBVBMETA_WRITER_H

#include <string>

#include "footer_format.h"

namespace android {
namespace fs_mgr {

std::string SerializeSuperAVBFooter(const SuperAVBFooter &input);
std::string SerializeSuperFooter(const SuperFooter &input);

} // namespace fs_mgr
} // namespace android

#endif /* LIBVBMETA_WRITER_H */