#include <processgroup/cgroup_descriptor.h>

#include <processgroup/util.h> // For flag values

CgroupDescriptor::CgroupDescriptor(uint32_t version, const std::string& name,
                                   const std::string& path, mode_t mode, const std::string& uid,
                                   const std::string& gid, uint32_t flags,
                                   uint32_t max_activation_depth)
    : controller_(version, flags, name, path, max_activation_depth),
      mode_(mode),
      uid_(uid),
      gid_(gid) {}

void CgroupDescriptor::set_mounted(bool mounted) {
    uint32_t flags = controller_.flags();
    if (mounted) {
        flags |= CGROUP_CONTROLLER_FLAG_MOUNTED;
    } else {
        flags &= ~CGROUP_CONTROLLER_FLAG_MOUNTED;
    }
    controller_.set_flags(flags);
}
