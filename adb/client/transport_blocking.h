/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include "transport.h"

// Abstraction for a blocking packet transport.
struct BlockingConnection {
    BlockingConnection() = default;
    BlockingConnection(const BlockingConnection& copy) = delete;
    BlockingConnection(BlockingConnection&& move) = delete;

    // Destroy a BlockingConnection. Formerly known as 'Close' in atransport.
    virtual ~BlockingConnection() = default;

    // Read/Write a packet. These functions are concurrently called from a transport's reader/writer
    // threads.
    virtual bool Read(apacket* packet) = 0;
    virtual bool Write(apacket* packet) = 0;

    virtual bool DoTlsHandshake(RSA* key, std::string* auth_key = nullptr) = 0;

    // Terminate a connection.
    // This method must be thread-safe, and must cause concurrent Reads/Writes to terminate.
    // Formerly known as 'Kick' in atransport.
    virtual void Close() = 0;

    // Terminate a connection, and reset it.
    virtual void Reset() = 0;
};

struct BlockingConnectionAdapter : public Connection {
    explicit BlockingConnectionAdapter(std::unique_ptr<BlockingConnection> connection);

    virtual ~BlockingConnectionAdapter();

    virtual bool Write(std::unique_ptr<apacket> packet) override final;

    virtual void Start() override final;
    virtual void Stop() override final;
    virtual bool DoTlsHandshake(RSA* key, std::string* auth_key) override final;

    virtual void Reset() override final;

  private:
    void StartReadThread() REQUIRES(mutex_);
    bool started_ GUARDED_BY(mutex_) = false;
    bool stopped_ GUARDED_BY(mutex_) = false;

    std::unique_ptr<BlockingConnection> underlying_;
    std::thread read_thread_ GUARDED_BY(mutex_);
    std::thread write_thread_ GUARDED_BY(mutex_);

    std::deque<std::unique_ptr<apacket>> write_queue_ GUARDED_BY(mutex_);
    std::mutex mutex_;
    std::condition_variable cv_;

    std::once_flag error_flag_;
};

struct FdConnection : public BlockingConnection {
    explicit FdConnection(unique_fd fd);
    ~FdConnection();

    bool Read(apacket* packet) override final;
    bool Write(apacket* packet) override final;
    bool DoTlsHandshake(RSA* key, std::string* auth_key) override final;

    void Close() override;
    virtual void Reset() override final { Close(); }

  private:
    bool DispatchRead(void* buf, size_t len);
    bool DispatchWrite(void* buf, size_t len);

    unique_fd fd_;
    std::unique_ptr<adb::tls::TlsConnection> tls_;
};
