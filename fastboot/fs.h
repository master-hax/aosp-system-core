#pragma once

#include <string>
#include <stdint.h>

struct fs_generator;

const struct fs_generator* fs_get_generator(const std::string& fs_type);
int fs_generator_generate(const struct fs_generator* gen, const char* fileName, long long partSize,
                          const std::string& initial_dir, unsigned eraseBlkSize = 0,
                          unsigned logicalBlkSize = 0, const bool wants_casefold = false,
                          const bool wants_projid = false);
