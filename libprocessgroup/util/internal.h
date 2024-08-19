#pragma once

#include <string>

#include <processgroup/util.h>

bool ReadDescriptorsFromFile(const std::string& file_name, CgroupDescriptorMap* descriptors);