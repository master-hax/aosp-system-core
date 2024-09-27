// Copyright (C) 2024 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PREFETCH_H
#define PREFETCH_H

int prefetch_replay(const char* path, const uint16_t* io_depth, const uint16_t* max_fds,
                    int8_t exit_on_error, const char* config_path, );

int prefetch_record(const char* path, int8_t debug, const uint16_t duration,
                    const uint64_t* trace_buffer_size, const char* tracing_subsystem,
                    int8_t setup_tracing, const char* tracing_instance);
#endif
