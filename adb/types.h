#pragma once

/*
 * Copyright (C) 2018 The Android Open Source Project
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

#if !defined(_WIN32)
#include <sys/uio.h>
#endif

#include <deque>
#include <vector>

#include <android-base/logging.h>

#include "sysdeps/memory.h"

struct BlockChain {
    using value_type = char;
    using block_type = std::string;
    using size_type = size_t;

    size_type size() const { return chain_length_ - begin_offset_ - end_offset_; }
    bool empty() const { return size() == 0; }

    // Split the first |len| bytes out of this chain into its own.
    BlockChain take_front(size_type len) {
        BlockChain head;

        if (len == 0) {
            return head;
        }
        CHECK_GE(size(), len);

        std::shared_ptr<const block_type> first_block = chain_.front();
        CHECK_GE(first_block->size(), begin_offset_);
        head.begin_offset_ = begin_offset_;
        head.append_shared(std::move(first_block));

        while (head.size() < len) {
            pop_front_block();
            CHECK(!chain_.empty());

            head.append_shared(chain_.front());
        }

        if (head.size() == len) {
            // Head takes full ownership of the last block it took.
            head.end_offset_ = 0;
            begin_offset_ = 0;
            pop_front_block();
        } else {
            // Head takes partial ownership of the last block it took.
            head.end_offset_ = head.chain_length_ - head.begin_offset_ - len;
            CHECK_GE(chain_.front()->size(), head.end_offset_);
            begin_offset_ = chain_.front()->size() - head.end_offset_;
        }

        return head;
    }

    // Add a nonempty block to the chain.
    // The end of the chain must be a complete block (i.e. end_offset_ == 0).
    void append(std::unique_ptr<const block_type> block) {
        CHECK_NE(0ULL, block->size());
        CHECK_EQ(0ULL, end_offset_);
        chain_length_ += block->size();
        chain_.emplace_back(std::move(block));
    }

    void append(block_type&& block) { append(std::make_unique<block_type>(std::move(block))); }

  private:
    // append, except takes a shared_ptr.
    // Private to prevent exterior mutation of blocks.
    void append_shared(std::shared_ptr<const block_type> block) {
        CHECK_NE(0ULL, block->size());
        CHECK_EQ(0ULL, end_offset_);
        chain_length_ += block->size();
        chain_.emplace_back(std::move(block));
    }

    // Drop the front block from the chain, and update chain_length_ appropriately.
    void pop_front_block() {
        chain_length_ -= chain_.front()->size();
        chain_.pop_front();
    }

    // Iterate over the blocks with a callback with an operator()(const char*, size_t).
    template <typename Fn>
    void iterate_blocks(Fn&& callback) const {
        if (chain_.size() == 0) {
            return;
        }

        for (size_t i = 0; i < chain_.size(); ++i) {
            const std::shared_ptr<const block_type>& block = chain_.at(i);
            const char* begin = block->data();
            size_t length = block->size();

            // Note that both of these conditions can be true if there's only one block.
            if (i == 0) {
                CHECK_GE(block->size(), begin_offset_);
                begin += begin_offset_;
                length -= begin_offset_;
            }

            if (i == chain_.size() - 1) {
                CHECK_GE(length, end_offset_);
                length -= end_offset_;
            }

            callback(begin, length);
        }
    }

  public:
    // Copy all of the blocks into a single block.
    template <typename CollectionType = block_type>
    CollectionType coalesce() const {
        CollectionType result;
        if (size() == 0) {
            return result;
        }

        result.reserve(size());

        iterate_blocks([&result](const char* data, size_t len) {
            result.insert(result.end(), data, data + len);
        });

        return result;
    }

#if !defined(_WIN32)
    // Get an iovec that can be used to write out all of the blocks.
    // TODO: Create an abstraction for iovec/WSABUF to allow us to use this on Windows as well.
    std::vector<struct iovec> iovecs() const {
        std::vector<struct iovec> result;
        iterate_blocks([&result](const char* data, size_t len) {
            struct iovec iov = {
                .iov_base = const_cast<char*>(data),
                .iov_len = len,
            };
            result.emplace_back(iov);
        });

        return result;
    }
#endif

  private:
    // Total length of all of the blocks in the chain.
    size_t chain_length_ = 0;

    size_t begin_offset_ = 0;
    size_t end_offset_ = 0;
    std::deque<std::shared_ptr<const block_type>> chain_;

  public:
    // TODO: Free list to avoid having to repeatedly allocate/zero initialize?
    static std::unique_ptr<BlockChain::block_type> AcquireBlock() {
        auto block = std::make_unique<BlockChain::block_type>();
        block->resize(256 * 1024);
        return block;
    }
};
