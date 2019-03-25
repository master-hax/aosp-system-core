#pragma once

#include <stddef.h>
#include "descriptors.h"
#include <vector>
#include <string>
#include <cutils/iosched_policy.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/resource.h>

#define NZPACKET_SERIALIZED_SIZE 4096

namespace android {
namespace init {

class NzPacket {
 public:
  std::string name;

  std::vector<std::string> args;
  std::vector<DescriptorInfo*> descriptors;
  std::vector<std::string> writepid_files;

  IoSchedClass ioprio_class;
  int ioprio_pri;
  int priority;

  uid_t uid;
  gid_t gid;
  std::vector<gid_t> supp_gids;

  std::string seclabel;
  std::string scon;

  bool has_cap_set;
  unsigned long long cap_set;
  int cap_set_size;

  std::vector<std::pair<int, rlimit>> rlimits;

  bool Serialize(char *buf);
  bool Deserialize(const char *buf);
};

}  // namespace init
}  // namespace android
