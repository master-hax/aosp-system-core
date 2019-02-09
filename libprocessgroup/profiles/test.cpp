
#include <string>

#include <gflags/gflags.h>
#include <jsonpb/json_schema_test.h>

#include "cgroups.pb.h"
#include "task_profiles.pb.h"

using namespace ::android::jsonpb;

DEFINE_string(root, "", "Root directory to fetch files from");
DEFINE_bool(verbose, false, "Print debug string of parsed files");

namespace android {
namespace profiles {

std::unique_ptr<JsonSchemaTestConfig> CreateCgroupsParam() {
    return std::make_unique<AbstractJsonSchemaTestConfig<Cgroups>>(
            FLAGS_root + "/system/etc/cgroups.json", FLAGS_verbose);
}
std::unique_ptr<JsonSchemaTestConfig> CreateTaskProfilesParam() {
    return std::make_unique<AbstractJsonSchemaTestConfig<TaskProfiles>>(
            FLAGS_root + "/system/etc/task_profiles.json", FLAGS_verbose);
}

INSTANTIATE_TEST_SUITE_P(LibProcessgroupProto, JsonSchemaTest,
                         ::testing::Values(&CreateCgroupsParam, &CreateTaskProfilesParam));

}  // namespace profiles
}  // namespace android

int main(int argc, char** argv) {
    using ::gflags::AllowCommandLineReparsing;
    using ::gflags::ParseCommandLineFlags;
    using ::testing::AddGlobalTestEnvironment;
    using ::testing::InitGoogleTest;

    AllowCommandLineReparsing();
    ParseCommandLineFlags(&argc, &argv, false /* remove flags */);

    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
