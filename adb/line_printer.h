// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef NINJA_LINE_PRINTER_H_
#define NINJA_LINE_PRINTER_H_

#include <stddef.h>
#include <string>

// Prints lines of text, possibly overprinting previously printed lines
// if the terminal supports it.
struct LinePrinter {
  LinePrinter();

  enum LineType { INFO, WARNING, ERROR };

  // Outputs the given line. INFO output will be overwritten.
  // WARNING and ERROR appear on a line to themselves.
  void Print(std::string to_print, LineType type);

  // If there's an INFO line, keep it. If not, do nothing.
  void KeepInfoLine();

 private:
  bool smart_terminal_;
  size_t current_line_length_;

#ifdef _WIN32
  void* console_;
#endif
};

#endif  // NINJA_LINE_PRINTER_H_
