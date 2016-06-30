/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LIBUNWINDSTACK_MAPS_H
#define _LIBUNWINDSTACK_MAPS_H

#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "Elf.h"
#include "MapInfo.h"

class Maps {
 public:
  Maps() = default;
  virtual ~Maps();

  MapInfo* Find(uint64_t pc);

  bool ParseLine(const char* line, MapInfo* map_info);

  virtual bool Parse();

  virtual const std::string GetMapsFile() { return ""; }

  typedef std::vector<MapInfo>::iterator iterator;
  iterator begin() { return maps_.begin(); }
  iterator end() { return maps_.end(); }

  typedef std::vector<MapInfo>::const_iterator const_iterator;
  const_iterator begin() const { return maps_.begin(); }
  const_iterator end() const { return maps_.end(); }

  size_t Total() { return maps_.size(); }

 protected:
  std::vector<MapInfo> maps_;
};

class MapsRemote : public Maps {
 public:
  MapsRemote(pid_t pid) : pid_(pid) {}
  virtual ~MapsRemote() = default;

  virtual const std::string GetMapsFile() override;

 private:
  pid_t pid_;
};

class MapsLocal : public MapsRemote {
 public:
  MapsLocal() : MapsRemote(getpid()) {}
  virtual ~MapsLocal() = default;
};

class MapsBuffer : public Maps {
 public:
  MapsBuffer(const char* buffer) : buffer_(buffer) {}
  virtual ~MapsBuffer() = default;

  bool Parse() override;

 private:
  const char* buffer_;
};

class MapsFile : public Maps {
 public:
  MapsFile(const std::string& file) : file_(file) {}
  virtual ~MapsFile() = default;

  const std::string GetMapsFile() override { return file_; }

 private:
  const std::string file_;
};

class MapsOffline : public Maps {
 public:
  MapsOffline(const std::string& file) : file_(file) {}
  virtual ~MapsOffline() = default;

  bool Parse() override;

 private:
  const std::string file_;
};

#endif  // _LIBUNWINDSTACK_MAPS_H
