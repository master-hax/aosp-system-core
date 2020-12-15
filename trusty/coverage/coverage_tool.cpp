#include <android-base/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstddef>
#include <iostream>
#include <string>

#include <trusty/coverage/coverage.h>

using android::trusty::coverage::CoverageRecord;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

__attribute__((weak)) extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */);

int coverage_tool_main(int argc, char* argv[], CoverageRecord& coverage, std::string module_name) {
    if (argc < 2) {
        printf("Usage: coverage_tool [FILE]...\n");
        printf("Gather coverage statistics by running each of the FILEs through the fuzzer\n");
        printf("This tool is designed to be run on the fuzzer corpus after fuzzing is complete.\n");
        return -1;
    }
    if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);

    for (int i = 2; i < argc; ++i) {
        std::string buffer;
        if (!android::base::ReadFileToString(std::string(argv[i]), &buffer)) {
            fprintf(stderr, "Could not read input file: %s\n", argv[i]);
        }
        LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(buffer.data()), buffer.length());
    }

    auto sancov_filename = module_name + "." + std::to_string(getpid()) + ".sancov";
    coverage.SaveSancovFile(sancov_filename);

    return 0;
}
