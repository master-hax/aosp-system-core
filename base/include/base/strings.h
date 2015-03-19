/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef BASE_STRINGS_H
#define BASE_STRINGS_H

#include <string>
#include <vector>

namespace android {
namespace base {

// TODO(danalbert): Should match the internal APIs more closely.
//
// Should make these changes sooner rather than later so we don't have to fixup
// too many users.
//
// * The internal APIs return a new vector rather than appending to the current
//   one.
// * Split("foo", "") would return {"f", "o", "o"} rather than {"foo"}. I'd opt
//   for Split("foo") doing this and Split("foo", "") being a compiler-time
//   error instead.
// * Split("", ",") would return {""} rather than {}. I'm not sure we want to
//   copy this behavior.

// Splits a string using the given separator character into a vector of strings.
// Empty strings will be omitted.
//
// Note that this appends the split string to the existing vector rather than
// clearing it.
void Split(const std::string& s, char separator,
           std::vector<std::string>* result);

// Same as the singe character separator version of Split, but splits on any of
// the separator characters.
//
// Using the empty string as a separator list results in the string not being
// split.
//
// Note that this appends the split string to the existing vector rather than
// clearing it.
void Split(const std::string& s, const char* separators,
           std::vector<std::string>* result);

// Trims whitespace off both ends of the given string.
std::string Trim(const std::string& s);

// Joins a vector of strings into a single string, using the given separator.
template <typename StringT>
std::string Join(const std::vector<StringT>& strings, char separator);

// Tests whether 's' starts with 'prefix'.
bool StartsWith(const std::string& s, const char* prefix);

// Tests whether 's' ends with 'suffix'.
bool EndsWith(const std::string& s, const char* suffix);

}  // namespace base
}  // namespace android

#endif  // BASE_STRINGS_H
