/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef ANDROID_BASE_STRINGPIECE_H
#define ANDROID_BASE_STRINGPIECE_H

#include <string.h>

#include <algorithm>
#include <string>

namespace android {
namespace base {

// A string-like object that points to a sized piece of memory.
//
// Functions or methods may use const StringPiece& parameters to accept either
// a "const char*" or a "string" value that will be implicitly converted to
// a StringPiece.  The implicit conversion means that it is often appropriate
// to include this .h file in other files rather than forward-declaring
// StringPiece as would be appropriate for most other Google classes.
template <typename CharT> class BasicStringPiece {
 public:
  // standard STL container boilerplate
  typedef CharT value_type;
  typedef const value_type* pointer;
  typedef const value_type& reference;
  typedef const value_type& const_reference;
  typedef size_t size_type;
  typedef ptrdiff_t difference_type;
  typedef const value_type* const_iterator;
  typedef const value_type* iterator;
  typedef std::reverse_iterator<const_iterator> const_reverse_iterator;
  typedef std::reverse_iterator<iterator> reverse_iterator;

  static constexpr size_type npos = size_type(-1);

  // We provide non-explicit singleton constructors so users can pass
  // in a "const char*" or a "string" wherever a "StringPiece" is
  // expected.
  BasicStringPiece() : ptr_(nullptr), length_(0) { }
  BasicStringPiece(const value_type* str)  // NOLINT implicit constructor desired
    : ptr_(str), length_((str == nullptr) ? 0 : std::char_traits<CharT>::length(str)) { }
  BasicStringPiece(const std::basic_string<CharT>& str)  // NOLINT implicit constructor desired
    : ptr_(str.data()), length_(str.size()) { }
  BasicStringPiece(const value_type* offset, size_t len) : ptr_(offset), length_(len) { }

  // data() may return a pointer to a buffer with embedded NULs, and the
  // returned buffer may or may not be null terminated.  Therefore it is
  // typically a mistake to pass data() to a routine that expects a NUL
  // terminated string.
  const value_type* data() const { return ptr_; }
  size_type size() const { return length_; }
  size_type length() const { return length_; }
  bool empty() const { return length_ == 0; }

  void clear() {
    ptr_ = nullptr;
    length_ = 0;
  }
  void set(const value_type* data_in, size_type len) {
    ptr_ = data_in;
    length_ = len;
  }
  void set(const value_type* str) {
    ptr_ = str;
    if (str != nullptr) {
      length_ = std::char_traits<CharT>::length(str);
    } else {
      length_ = 0;
    }
  }
  void set(const void* data_in, size_type len) {
    ptr_ = reinterpret_cast<const value_type*>(data_in);
    length_ = len;
  }

  value_type operator[](size_type i) const {
#ifndef NDEBUG
    assert(i < length_);
#endif
    return ptr_[i];
  }

  void remove_prefix(size_type n) {
    ptr_ += n;
    length_ -= n;
  }

  void remove_suffix(size_type n) {
    length_ -= n;
  }

  int compare(const BasicStringPiece<CharT>& x) const {
    int r = memcmp(ptr_, x.ptr_, std::min(length_, x.length_));
    if (r == 0) {
      if (length_ < x.length_) r = -1;
      else if (length_ > x.length_) r = +1;
    }
    return r;
  }

  std::basic_string<CharT> as_string() const {
    return ToString();
  }
  // We also define ToString() here, since many other string-like
  // interfaces name the routine that converts to a C++ string
  // "ToString", and it's confusing to have the method that does that
  // for a StringPiece be called "as_string()".  We also leave the
  // "as_string()" method defined here for existing code.
  std::basic_string<CharT> ToString() const {
    return std::string(data(), size());
  }

  // Does "this" start with "x"
  bool starts_with(const BasicStringPiece<CharT>& x) const {
    return ((length_ >= x.length_) &&
            (memcmp(ptr_, x.ptr_, x.length_) == 0));
  }

  // Does "this" end with "x"
  bool ends_with(const BasicStringPiece<CharT>& x) const {
    return ((length_ >= x.length_) &&
            (memcmp(ptr_ + (length_-x.length_), x.ptr_, x.length_) == 0));
  }

  iterator begin() const { return ptr_; }
  iterator end() const { return ptr_ + length_; }
  const_reverse_iterator rbegin() const {
    return const_reverse_iterator(ptr_ + length_);
  }
  const_reverse_iterator rend() const {
    return const_reverse_iterator(ptr_);
  }

  size_type copy(value_type* buf, size_type n, size_type pos = 0) const {
    size_type ret = std::min(length_ - pos, n);
    memcpy(buf, ptr_ + pos, ret);
    return ret;
  }

  size_type find(const BasicStringPiece<CharT>& s, size_type pos = 0) const {
    if (length_ == 0 || pos > static_cast<size_type>(length_)) return npos;
    const CharT* result = std::search(ptr_ + pos, ptr_ + length_, s.ptr_, s.ptr_ + s.length_);
    const size_type xpos = result - ptr_;
    return xpos + s.length_ <= length_ ? xpos : npos;
  }

  size_type find(value_type c, size_type pos = 0) const {
    if (length_ == 0 || pos >= length_) return npos;
    const CharT* result = std::find(ptr_ + pos, ptr_ + length_, c);
    return result != ptr_ + length_ ? result - ptr_ : npos;
  }

  size_type rfind(const BasicStringPiece<CharT>& s, size_type pos = npos) const {
    if (length_ < s.length_) return npos;
    const size_t ulen = length_;
    if (s.length_ == 0) return std::min(ulen, pos);

    const CharT* last = ptr_ + std::min(ulen - s.length_, pos) + s.length_;
    const CharT* result = std::find_end(ptr_, last, s.ptr_, s.ptr_ + s.length_);
    return result != last ? result - ptr_ : npos;
  }

  size_type rfind(value_type c, size_type pos = npos) const {
    if (length_ == 0) return npos;
    for (int i = std::min(pos, static_cast<size_type>(length_ - 1)); i >= 0; --i) {
      if (ptr_[i] == c) {
        return i;
      }
    }
    return npos;
  }

  bool contains(const BasicStringPiece<CharT>& s) {
    return find(s, 0) != npos;
  }

  BasicStringPiece<CharT> substr(size_type pos, size_type n = npos) const {
    if (pos > static_cast<size_type>(length_)) pos = length_;
    if (n > length_ - pos) n = length_ - pos;
    return BasicStringPiece<CharT>(ptr_ + pos, n);
  }

 private:
  // Pointer to data, not necessarily zero terminated.
  const value_type* ptr_;
  // Length of data.
  size_type length_;
};

// This large function is defined inline so that in a fairly common case where
// one of the arguments is a literal, the compiler can elide a lot of the
// following comparisons.
template <typename CharT>
inline bool operator==(const BasicStringPiece<CharT>& x, const BasicStringPiece<CharT>& y) {
  typename BasicStringPiece<CharT>::size_type len = x.size();
  if (len != y.size()) {
    return false;
  }

  const CharT* p1 = x.data();
  const CharT* p2 = y.data();
  if (p1 == p2) {
    return true;
  }
  if (len == 0) {
    return true;
  }

  // Test last byte in case strings share large common prefix
  if (p1[len-1] != p2[len-1]) return false;
  if (len == 1) return true;

  // At this point we can, but don't have to, ignore the last byte.  We use
  // this observation to fold the odd-length case into the even-length case.
  len &= ~1;

  return memcmp(p1, p2, len) == 0;
}

/*
template <>
inline bool operator==(const BasicStringPiece<char>& x, const char* y) {
  if (y == nullptr) { // Because StringPiece(nullptr) is the empty string piece
    return x.size() == 0;
  } else {
    return strncmp(x.data(), y, x.size()) == 0 && y[x.size()] == '\0';
  }
}
*/

template <typename CharT>
inline bool operator!=(const BasicStringPiece<CharT>& x, const BasicStringPiece<CharT>& y) {
  return !(x == y);
}

template <typename CharT>
inline bool operator!=(const BasicStringPiece<CharT>& x, const CharT* y) {
  return !(x == y);
}

template <typename CharT>
inline bool operator<(const BasicStringPiece<CharT>& x, const BasicStringPiece<CharT>& y) {
  return x.compare(y) < 0;
}

template <typename CharT>
inline bool operator>(const BasicStringPiece<CharT>& x, const BasicStringPiece<CharT>& y) {
  return y < x;
}

template <typename CharT>
inline bool operator<=(const BasicStringPiece<CharT>& x, const BasicStringPiece<CharT>& y) {
  return !(x > y);
}

template <typename CharT>
inline bool operator>=(const BasicStringPiece<CharT>& x, const BasicStringPiece<CharT>& y) {
  return !(x < y);
}

template <typename CharT>
extern std::ostream& operator<<(std::ostream& o, const BasicStringPiece<CharT>& piece);


template <typename CharT> struct StringPieceHash {
  size_t operator()(const BasicStringPiece<CharT>& s) const {
    size_t result = 0;
    for (CharT c : s) {
      result = (result * 131) + c;
    }
    return result;
  }
};


using StringPiece = BasicStringPiece<char>;
using StringPiece16 = BasicStringPiece<char16_t>;

}  // namespace base
}  // namespace android

#endif  // ANDROID_BASE_STRINGPIECE_H
