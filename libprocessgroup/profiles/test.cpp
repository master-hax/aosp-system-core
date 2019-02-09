#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <optional>

#include <android-base/file.h>
#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <processgroup/parse_message.h>

#include "cgroups.pb.h"
#include "task_profiles.pb.h"

DEFINE_string(root, "", "Root directory to fetch files from");

namespace android {
namespace profiles {

static constexpr char kCgroupsPath[] = "/system/etc/cgroups.json";
static constexpr char kTaskProfilesPath[] = "/system/etc/task_profiles.json";

struct ProfilesParseTest : public ::testing::Test {};

TEST_F(ProfilesParseTest, Cgroups) {
  std::string content;
  ASSERT_TRUE(android::base::ReadFileToString(FLAGS_root + kCgroupsPath, &content))
      << "Cannot read " << FLAGS_root << kCgroupsPath;
  auto cgroups = android::JsonStringToMessage<Cgroups>(content);
  EXPECT_TRUE(cgroups.ok()) << "Invalid format of file " << FLAGS_root << kCgroupsPath << ": "
                            << cgroups.error();
}

TEST_F(ProfilesParseTest, TaskProfiles) {
  std::string content;
  ASSERT_TRUE(android::base::ReadFileToString(FLAGS_root + kTaskProfilesPath, &content))
      << "Cannot read " << FLAGS_root << kTaskProfilesPath;
  auto cgroups = android::JsonStringToMessage<TaskProfiles>(content);
  EXPECT_TRUE(cgroups.ok()) << "Invalid format of file " << FLAGS_root << kTaskProfilesPath << ": "
                            << cgroups.error();
}

}  // namespace profiles
}  // namespace android

int main(int argc, char **argv) {
  ::gflags::AllowCommandLineReparsing();
  ::gflags::ParseCommandLineFlags(&argc, &argv, false /* remove flags */);

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
