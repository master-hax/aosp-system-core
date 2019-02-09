
#include <string>

#include <gflags/gflags.h>
#include <jsonpb/json_schema_test.h>

#include "cgroups.pb.h"
#include "task_profiles.pb.h"

namespace android {

namespace jsonpb {
JsonSchemaTestEnvironment* gJsonSchemaTestEnvironment = nullptr;
}  // namespace jsonpb

namespace profiles {

struct CgroupsTestParam {
    using Prototype = Cgroups;
    std::string path_{"/system/etc/cgroups.json"};
};

struct TaskProfilesTestParam {
    using Prototype = TaskProfiles;
    std::string path_{"/system/etc/task_profiles.json"};
};

using AllJsonSchemaTestParams = ::testing::Types<CgroupsTestParam, TaskProfilesTestParam>;
}  // namespace profiles

// Test suite needs to be instantiated in the same namespace as JsonSchemaTest.
namespace jsonpb {
INSTANTIATE_TYPED_TEST_SUITE_P(LibProcessgroupProto, JsonSchemaTest,
                               profiles::AllJsonSchemaTestParams);

}  // namespace jsonpb
}  // namespace android

DEFINE_string(root, "", "Root directory to fetch files from");
DEFINE_bool(verbose, false, "Print debug string of parsed files");

int main(int argc, char** argv) {
    using ::android::jsonpb::gJsonSchemaTestEnvironment;
    using ::android::jsonpb::JsonSchemaTestEnvironment;
    using ::gflags::AllowCommandLineReparsing;
    using ::gflags::ParseCommandLineFlags;
    using ::testing::AddGlobalTestEnvironment;
    using ::testing::InitGoogleTest;

    AllowCommandLineReparsing();
    ParseCommandLineFlags(&argc, &argv, false /* remove flags */);

    gJsonSchemaTestEnvironment = static_cast<JsonSchemaTestEnvironment*>(
            AddGlobalTestEnvironment(new JsonSchemaTestEnvironment()));
    gJsonSchemaTestEnvironment->root_ = FLAGS_root;
    gJsonSchemaTestEnvironment->verbose_ = FLAGS_verbose;

    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
