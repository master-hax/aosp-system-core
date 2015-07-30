// Copyright (C) 2015 The Android Open Source Project
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

#include "tokenizer.h"

#include "input_stream.h"

namespace init {

Tokenizer::Tokenizer(InputStream* stream)
    : stream_(stream),
      buffer_(nullptr),
      size_(0),
      eof_(false),
      pos_(0),
      tok_start_(0),
      in_text_(false) {
  current_.type = TOK_START;
  GetData();
}

Tokenizer::~Tokenizer() {}

const Tokenizer::Token& Tokenizer::current() {
  return current_;
}

bool Tokenizer::Next() {
  while (!eof_) {
    AdvWhiteSpace();

    // Check for comments.
    if (cur_char_ == '#') {
      AdvChar();
      // Skip rest of line
      while (!eof_ && cur_char_ != '\n') {
        AdvChar();
      }
    }

    if (eof_) {
      break;
    }

    if (cur_char_ == '\0') {
      AdvChar();
    } else if (cur_char_ == '\n') {
      current_.type = TOK_NEWLINE;
      current_.text.clear();
      AdvChar();
      return true;
    } else if (cur_char_ == '\\') {
      AdvChar();  // skip backslach
      // Skip rest of line
      AdvUntil('\n');
      AdvChar();  // skip \n
    } else if (cur_char_ == '\"') {
      AdvChar();
      StartText();
      // Grab everything until the next quote.
      AdvUntil('\"');
      EndText();
      AdvChar();  // skip quote.
      return true;
    } else {
      StartText();
      AdvText();
      EndText();
      return true;
    }
  }
  current_.type = TOK_END;
  current_.text.clear();
  return false;
}

void Tokenizer::GetData() {
  if (eof_) {
    cur_char_ = '\0';
    return;
  }

  if (in_text_ && (tok_start_ < size_)) {
    current_.text.append(buffer_ + tok_start_, size_ - tok_start_);
    tok_start_ = 0;
  }

  const void* data = nullptr;
  pos_ = 0;
  if (!stream_->GetData(&data, &size_)) {
    eof_ = true;
    size_ = 0;
    cur_char_ = '\0';
    return;
  }

  buffer_ = static_cast<const char*>(data);
  cur_char_ = buffer_[0];
}

void Tokenizer::AdvChar() {
  pos_++;
  if (pos_ < size_) {
    cur_char_ = buffer_[pos_];
  } else {
    GetData();
  }
}

void Tokenizer::AdvWhiteSpace() {
  while (cur_char_ == '\t' || cur_char_ == '\r' || cur_char_ == ' ') {
    AdvChar();
  }
}

void Tokenizer::AdvUntil(char x) {
  while (!eof_ && cur_char_ != x) {
    AdvChar();
  }
}

void Tokenizer::AdvText() {
  while (cur_char_ != '\t' && cur_char_ != '\r' && cur_char_ != '\0' &&
         cur_char_ != ' ' && cur_char_ != '\n' && cur_char_ != '#') {
    AdvChar();
  }
}

void Tokenizer::StartText() {
  current_.text.clear();
  tok_start_ = pos_;
  current_.type = TOK_TEXT;
  in_text_ = true;
}

void Tokenizer::EndText() {
  if (!eof_ && pos_ != tok_start_) {
    current_.text.append(buffer_ + tok_start_, pos_ - tok_start_);
  }
  in_text_ = false;
}

}  // namespace init