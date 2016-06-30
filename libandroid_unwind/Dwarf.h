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

#ifndef _LIBANDROID_UNWIND_DWARF_H
#define _LIBANDROID_UNWIND_DWARF_H

#include "Memory.h"

class Dwarf {
 public:
  Dwarf(Memory* memory) : memory_(memory) { }
  virtual ~Dwarf() = default;

 private:
  std::stack<> stack_;
};

class Dwarf1 : public Dwarf {
 public:
  Dwarf1(Memory* memory) : Dwarf(memory) { }
  virtual ~Dwarf1() = default;

 private:
};

class Dwarf2 : public Dwarf {
 public:
  Dwarf2(Memory* memory) : Dwarf(memory) { }
  virtual ~Dwarf2() = default;

 private:
};

class Dwarf3 : public Dwarf {
 public:
  Dwarf3(Memory* memory) : Dwarf(memory) { }
  virtual ~Dwarf3() = default;

 private:
};

class Dwarf4 : public Dwarf {
 public:
  Dwarf4(Memory* memory) : Dwarf(memory) { }
  virtual ~Dwarf4() = default;

 private:
};

#endif  // _LIBANDROID_UNWIND_DWARF_H
