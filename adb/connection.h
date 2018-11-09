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

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <android-base/thread_annotations.h>

#include "adb.h"
#include "adb_unique_fd.h"
#include "types.h"

// Abstraction for a non-blocking packet transport.
struct Connection {
    Connection() = default;
    virtual ~Connection() = default;

    void SetTransportName(std::string transport_name) {
        transport_name_ = std::move(transport_name);
    }

    using ReadCallback = std::function<bool(Connection*, std::unique_ptr<apacket>)>;
    void SetReadCallback(ReadCallback callback) {
        CHECK(!read_callback_);
        read_callback_ = callback;
    }

    // Called after the Connection has terminated, either by an error or because Stop was called.
    using ErrorCallback = std::function<void(Connection*, const std::string&)>;
    void SetErrorCallback(ErrorCallback callback) {
        CHECK(!error_callback_);
        error_callback_ = callback;
    }

    virtual bool Write(std::unique_ptr<apacket> packet) = 0;

    virtual void Start() = 0;
    virtual void Stop() = 0;

    // Stop, and reset the device if it's a USB connection.
    virtual void Reset();

    void HandleError(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3)));

    std::string transport_name_;
    ReadCallback read_callback_;
    ErrorCallback error_callback_;

    static std::unique_ptr<Connection> FromFd(unique_fd fd);

  private:
    std::once_flag error_flag_;
};

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

    virtual void Reset() override final;

    bool started_ GUARDED_BY(mutex_) = false;
    bool stopped_ GUARDED_BY(mutex_) = false;

    std::unique_ptr<BlockingConnection> underlying_;
    std::thread read_thread_ GUARDED_BY(mutex_);
    std::thread write_thread_ GUARDED_BY(mutex_);

    std::deque<std::unique_ptr<apacket>> write_queue_ GUARDED_BY(mutex_);
    std::mutex mutex_;
    std::condition_variable cv_;
};

struct FdConnection : public BlockingConnection {
    explicit FdConnection(unique_fd fd) : fd_(std::move(fd)) {}

    bool Read(apacket* packet) override final;
    bool Write(apacket* packet) override final;

    void Close() override;
    virtual void Reset() override final { Close(); }

  private:
    unique_fd fd_;
};

struct UsbConnection : public BlockingConnection {
    explicit UsbConnection(usb_handle* handle) : handle_(handle) {}
    ~UsbConnection();

    bool Read(apacket* packet) override final;
    bool Write(apacket* packet) override final;

    void Close() override final;
    virtual void Reset() override final;

    usb_handle* handle_;
};
