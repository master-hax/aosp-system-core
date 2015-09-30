/*
 * Copyright (C) 2005 The Android Open Source Project
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

#include <shared_ptr>
/**
  Not thread-safe (nor SharedBuffer was AFAICS). Race condition between unique() and reset()
  */
template <class T>
class AsCopyOnWrite : private std::shared_ptr<T> {
public:
    const T& get() const {
        return *this;
    }
    T& getToWrite() const {
        // If someone else is using the shared object, make our copy.
        if(!unique()) {
            reset(new T(*this));
        }
        return *this;
    }
}

// Example usage.
template <class T>
class SergioVector<T> : private AsCopyOnWrite<std::vector> {
public:
   size_t size() {
       return get().size();
   }
   void edit(int pos, T& val) {
       return getToWrite()[pos] = val;
   }
// Etc.
}
