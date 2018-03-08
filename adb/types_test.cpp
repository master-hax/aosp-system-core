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

#include <gtest/gtest.h>

#include "sysdeps/memory.h"
#include "types.h"

static std::unique_ptr<BlockChain::block_type> create_block(const std::string& string) {
    // TODO: std::make_unique when Windows gets it.
    return std::unique_ptr<BlockChain::block_type>(
        new BlockChain::block_type(string.begin(), string.end()));
}

static std::unique_ptr<BlockChain::block_type> create_block(char value, size_t len) {
    // TODO: std::make_unique when Windows gets it.
    auto block = std::make_unique<BlockChain::block_type>();
    block->resize(len);
    memset(&(*block)[0], value, len);
    return block;
}

template <typename T>
static std::unique_ptr<BlockChain::block_type> copy_block(T&& block) {
    return std::unique_ptr<BlockChain::block_type>(new BlockChain::block_type(*block));
}

TEST(BlockChain, empty) {
    // Empty BlockChain.
    BlockChain bc;
    CHECK_EQ(0ULL, bc.coalesce().size());
}

TEST(BlockChain, single_block) {
    // A single block.
    auto block = create_block('x', 100);
    BlockChain bc;
    bc.append(copy_block(block));
    ASSERT_EQ(100ULL, bc.size());
    auto coalesced = bc.coalesce();
    ASSERT_EQ(*block, coalesced);
}

TEST(BlockChain, single_block_split) {
    // One block split.
    BlockChain bc;
    bc.append(create_block("foobar"));
    BlockChain foo = bc.take_front(3);
    ASSERT_EQ(3ULL, foo.size());
    ASSERT_EQ(3ULL, bc.size());
    ASSERT_EQ(*create_block("foo"), foo.coalesce());
    ASSERT_EQ(*create_block("bar"), bc.coalesce());
}

TEST(BlockChain, aligned_split) {
    BlockChain bc;
    bc.append(create_block("foo"));
    bc.append(create_block("bar"));
    bc.append(create_block("baz"));
    ASSERT_EQ(9ULL, bc.size());

    BlockChain foo = bc.take_front(3);
    ASSERT_EQ(3ULL, foo.size());
    ASSERT_EQ(*create_block("foo"), foo.coalesce());

    BlockChain bar = bc.take_front(3);
    ASSERT_EQ(3ULL, bar.size());
    ASSERT_EQ(*create_block("bar"), bar.coalesce());

    BlockChain baz = bc.take_front(3);
    ASSERT_EQ(3ULL, baz.size());
    ASSERT_EQ(*create_block("baz"), baz.coalesce());

    ASSERT_EQ(0ULL, bc.size());
}

TEST(BlockChain, misaligned_split) {
    BlockChain bc;
    bc.append(create_block("foo"));
    bc.append(create_block("bar"));
    bc.append(create_block("baz"));
    bc.append(create_block("qux"));
    bc.append(create_block("quux"));

    // Aligned left, misaligned right, across multiple blocks.
    BlockChain foob = bc.take_front(4);
    ASSERT_EQ(4ULL, foob.size());
    ASSERT_EQ(*create_block("foob"), foob.coalesce());

    // Misaligned left, misaligned right, in one block.
    BlockChain a = bc.take_front(1);
    ASSERT_EQ(1ULL, a.size());
    ASSERT_EQ(*create_block("a"), a.coalesce());

    // Misaligned left, misaligned right, across two blocks.
    BlockChain rba = bc.take_front(3);
    ASSERT_EQ(3ULL, rba.size());
    ASSERT_EQ(*create_block("rba"), rba.coalesce());

    // Misaligned left, misaligned right, across three blocks.
    BlockChain zquxquu = bc.take_front(7);
    ASSERT_EQ(7ULL, zquxquu.size());
    ASSERT_EQ(*create_block("zquxquu"), zquxquu.coalesce());

    ASSERT_EQ(1ULL, bc.size());
    ASSERT_EQ(*create_block("x"), bc.coalesce());
}
