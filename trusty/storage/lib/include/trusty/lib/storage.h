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

#pragma once

#include <stdint.h>
#include <trusty/interface/storage.h>

#define STORAGE_MAX_NAME_LENGTH_BYTES 64

__BEGIN_DECLS

typedef int storage_session_t;
typedef uint32_t file_handle_t;
typedef uint64_t storage_off_t;

/**
 * storage_ops_flags - storage related operation flags
 * @STORAGE_OP_COMPLETE: forces to commit current transaction
 */
enum storage_ops_flags {
    STORAGE_OP_COMPLETE = 0x1,
};

/**
 * storage_open_session() - Opens a storage session.
 * @device:    device node for talking with Trusty
 * @session_p: pointer to location in which to store session handle
 *             in case of success.
 *
 * Return: 0 on success, or an error code < 0 on failure.
 */
int storage_open_session(const char *device, storage_session_t *session_p, const char *port);

/**
 * storage_close_session() - Closes the session.
 * @session: the session to close
 *
 */
void storage_close_session(storage_session_t session);

/**
 * storage_open_file_ext() - Opens a file
 * @session:  the storage_session_t returned from a call to storage_open_session
 * @handle_p: pointer to location in which to store file handle in case of success
 * @name:     a null-terminated string identifier of the file to open.
 *            Cannot be more than STORAGE_MAX_NAME_LENGTH_BYTES in length.
 * @flags:    A bitmask consisting any storage_file_flag value or'ed together:
 * - STORAGE_FILE_OPEN_CREATE:           if this file does not exist, create it.
 * - STORAGE_FILE_OPEN_CREATE_EXCLUSIVE: when specified, opening file with
 *                                       STORAGE_OPEN_FILE_CREATE flag will
 *                                       fail if the file already exists.
 *                                       Only meaningful if used in combination
 *                                       with STORAGE_FILE_OPEN_CREATE flag.
 * - STORAGE_FILE_OPEN_TRUNCATE: if this file already exists, discard existing
 *                               content and open it as a new file. No change
 *                               in semantics if the  file does not exist.
 * Return: 0 on success, or an error code < 0 on failure.
 *
 */
int storage_open_file_ext(storage_session_t session, file_handle_t *handle_p,
                          const char *name, uint32_t flags, uint32_t opflags);


static int storage_open_file(storage_session_t session, file_handle_t *handle_p,
                             const char *name, uint32_t flags)
{
    return storage_open_file_ext(session, handle_p, name, flags, STORAGE_OP_COMPLETE);
}

/**
 * storage_close_file() - Closes a file.
 * @session: the storage_session_t returned from a call to storage_open_session
 * @handle: the file_handle_t retrieved from storage_open_file
 *
 */
void storage_close_file(storage_session_t session, file_handle_t handle);

/**
 * storage_delete_file_ext - Deletes a file.
 * @session: the storage_session_t returned from a call to storage_open_session
 * @name: the name of the file to delete
 * @opflags: a combination of @storage_op_flags
 *
 * Return: 0 on success, or an error code < 0 on failure.
 */
int storage_delete_file_ext(storage_session_t session, const char *name,
                            uint32_t opflags);

static int storage_delete_file(storage_session_t session, const char *name)
{
    return storage_delete_file_ext(session, name, STORAGE_OP_COMPLETE);
}

/**
 * storage_read() - Reads a file at a given offset.
 * @session: the storage_session_t returned from a call to storage_open_session
 * @handle: the file_handle_t retrieved from storage_open_file
 * @off: the start offset from whence to read in the file
 * @buf: the buffer in which to write the data read
 * @size: the size of buf and number of bytes to read
 *
 * Return: the number of bytes read on success, negative error code on failure
 *
 */
int storage_read(storage_session_t session, file_handle_t handle,
                 storage_off_t off, void *buf, size_t size);

/**
 * storage_write_ext() - Writes to a file at a given offset. Grows the file if necessary.
 * @session: the storage_session_t returned from a call to storage_open_session
 * @handle: the file_handle_t retrieved from storage_open_file
 * @off: the start offset from whence to write in the file
 * @buf: the buffer containing the data to write
 * @size: the size of buf and number of bytes to write
 * @opflags: a combination of @storage_op_flags
 *
 * Return: the number of bytes written on success, negative error code on failure
 *
 */
int storage_write_ext(storage_session_t session, file_handle_t handle,
                      storage_off_t off, const void *buf, size_t size,
                      uint32_t opflags);

static int storage_write(storage_session_t session, file_handle_t handle,
                  storage_off_t off, const void *buf, size_t size)
{
    return storage_write_ext(session, handle, off, buf, size, STORAGE_OP_COMPLETE);
}

/**
 * storage_set_file_size_ext() - Sets the size of the file.
 * @session: the storage_session_t returned from a call to storage_open_session
 * @handle: the file_handle_t retrieved from storage_open_file
 * @off: the number of bytes to set as the new size of the file
 * @opflags: a combination of @storage_op_flags
 *
 * Return: 0 on success, negative error code on failure.
 *
 */
int storage_set_file_size_ext(storage_session_t session, file_handle_t handle,
                              storage_off_t file_size, uint32_t opflags);

static int storage_set_file_size(storage_session_t session, file_handle_t handle,
                                 storage_off_t file_size)
{
    return storage_set_file_size_ext(session, handle, file_size, STORAGE_OP_COMPLETE);
}

/**
 * storage_get_file_size() - Gets the size of the file.
 * @session: the storage_session_t returned from a call to storage_open_session
 * @handle: the file_handle_t retrieved from storage_open_file
 * @size: pointer to storage_off_t in which to store the file size
 *
 * Return: 0 on success, negative error code on failure.
 *
 */
int storage_get_file_size(storage_session_t session, file_handle_t handle,
                          storage_off_t *size);


/**
 * storage_end_transaction: End current transaction
 * @session: the storage_session_t returned from a call to storage_open_session
 * @complete: if true, commit current transaction, discard it otherwise
 *
 * Return: 0 on success, negative error code on failure.
 */
int storage_end_transaction(storage_session_t session, bool complete);


__END_DECLS
