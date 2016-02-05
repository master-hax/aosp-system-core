/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <string.h>

#include <algorithm>
#include <type_traits>
#include <utility>

#include <hardware/nvram.h>
#include <nvram/nvram_messages.h>

#include "nvram_ipc.h"

namespace {

struct TrustyNvramDevice {
  struct nvram_device device;
  nvram::TrustyNvramProxy nvram_proxy;
};

// Make sure |TrustyNvramDevice| is a standard layout type. This guarantees that
// casting from/to the type of the first non-static member (i.e. |device_|)
// works as expected.
static_assert(std::is_standard_layout<TrustyNvramDevice>::value,
              "TrustyNvramDevice must be a standard layout type.");

// Sends a request to the Trusty app and returns the result code.
template <nvram::Command command,
          typename RequestPayload,
          typename ResponsePayload>
nvram_result_t Execute(const struct nvram_device* device,
                       RequestPayload&& request_payload,
                       ResponsePayload* response_payload) {
  TrustyNvramDevice* trusty_nvram_device = reinterpret_cast<TrustyNvramDevice*>(
      const_cast<struct nvram_device*>(device));

  nvram::Request request;
  request.payload.Activate<command>() = std::move(request_payload);
  nvram::Response response;
  if (!trusty_nvram_device->nvram_proxy.Execute(request, &response)) {
    return NV_RESULT_INTERNAL_ERROR;
  }

  if (response.result != NV_RESULT_SUCCESS) {
    return response.result;
  }

  ResponsePayload* response_payload_ptr = response.payload.get<command>();
  if (!response_payload_ptr) {
    return NV_RESULT_INTERNAL_ERROR;
  }
  *response_payload = std::move(*response_payload_ptr);

  return NV_RESULT_SUCCESS;
}

// All the HAL methods need to be callable from C code.
extern "C" {

nvram_result_t trusty_get_total_size_in_bytes(const struct nvram_device* device,
                                              uint64_t* total_size) {
  nvram::GetInfoRequest get_info_request;
  nvram::GetInfoResponse get_info_response;
  nvram_result_t result = Execute<nvram::COMMAND_GET_INFO>(
      device, std::move(get_info_request), &get_info_response);
  *total_size = get_info_response.total_size;
  return result;
}

nvram_result_t trusty_get_available_size_in_bytes(
    const struct nvram_device* device,
    uint64_t* available_size) {
  nvram::GetInfoRequest get_info_request;
  nvram::GetInfoResponse get_info_response;
  nvram_result_t result = Execute<nvram::COMMAND_GET_INFO>(
      device, std::move(get_info_request), &get_info_response);
  *available_size = get_info_response.available_size;
  return result;
}

nvram_result_t trusty_get_max_spaces(const struct nvram_device* device,
                                     uint32_t* num_spaces) {
  nvram::GetInfoRequest get_info_request;
  nvram::GetInfoResponse get_info_response;
  nvram_result_t result = Execute<nvram::COMMAND_GET_INFO>(
      device, std::move(get_info_request), &get_info_response);
  *num_spaces = get_info_response.max_spaces;
  return result;
}

nvram_result_t trusty_get_space_list(const struct nvram_device* device,
                                     uint32_t max_list_size,
                                     uint32_t* space_index_list,
                                     uint32_t* list_size) {
  nvram::GetInfoRequest get_info_request;
  nvram::GetInfoResponse get_info_response;
  nvram_result_t result = Execute<nvram::COMMAND_GET_INFO>(
      device, std::move(get_info_request), &get_info_response);

  if (space_index_list) {
    *list_size = std::min(get_info_response.space_list.size(),
                          static_cast<size_t>(max_list_size));
    for (size_t i = 0; i < *list_size; ++i) {
      space_index_list[i] = get_info_response.space_list[i];
    }
  } else {
    *list_size = get_info_response.space_list.size();
  }

  return result;
}

nvram_result_t trusty_get_space_size(const struct nvram_device* device,
                                     uint32_t index,
                                     uint64_t* size) {
  nvram::GetSpaceInfoRequest get_space_info_request;
  get_space_info_request.index = index;
  nvram::GetSpaceInfoResponse get_space_info_response;
  nvram_result_t result = Execute<nvram::COMMAND_GET_SPACE_INFO>(
      device, std::move(get_space_info_request), &get_space_info_response);
  *size = get_space_info_response.size;
  return result;
}

nvram_result_t trusty_get_space_controls(const struct nvram_device* device,
                                         uint32_t index,
                                         uint32_t max_list_size,
                                         nvram_control_t* control_list,
                                         uint32_t* list_size) {
  nvram::GetSpaceInfoRequest get_space_info_request;
  get_space_info_request.index = index;
  nvram::GetSpaceInfoResponse get_space_info_response;
  nvram_result_t result = Execute<nvram::COMMAND_GET_SPACE_INFO>(
      device, std::move(get_space_info_request), &get_space_info_response);

  if (control_list) {
    *list_size = std::min(get_space_info_response.controls.size(),
                          static_cast<size_t>(max_list_size));
    for (size_t i = 0; i < *list_size; ++i) {
      control_list[i] = get_space_info_response.controls[i];
    }
  } else {
    *list_size = get_space_info_response.controls.size();
  }

  return result;
}

nvram_result_t trusty_is_space_locked(const struct nvram_device* device,
                                      uint32_t index,
                                      int* write_lock_enabled,
                                      int* read_lock_enabled) {
  nvram::GetSpaceInfoRequest get_space_info_request;
  get_space_info_request.index = index;
  nvram::GetSpaceInfoResponse get_space_info_response;
  nvram_result_t result = Execute<nvram::COMMAND_GET_SPACE_INFO>(
      device, std::move(get_space_info_request), &get_space_info_response);
  *write_lock_enabled = get_space_info_response.write_locked;
  *read_lock_enabled = get_space_info_response.read_locked;
  return result;
}

nvram_result_t trusty_create_space(const struct nvram_device* device,
                                   uint32_t index,
                                   uint64_t size_in_bytes,
                                   nvram_control_t* control_list,
                                   uint32_t list_size,
                                   uint8_t* authorization_value,
                                   uint32_t authorization_value_size) {
  nvram::CreateSpaceRequest create_space_request;
  create_space_request.index = index;
  create_space_request.size = size_in_bytes;
  if (!create_space_request.controls.Resize(list_size)) {
    return NV_RESULT_INTERNAL_ERROR;
  }
  for (size_t i = 0; i < list_size; ++i) {
    create_space_request.controls[i] = control_list[i];
  }
  if (!create_space_request.authorization_value.Assign(
          authorization_value, authorization_value_size)) {
    return NV_RESULT_INTERNAL_ERROR;
  }
  nvram::CreateSpaceResponse create_space_response;
  return Execute<nvram::COMMAND_CREATE_SPACE>(
      device, std::move(create_space_request), &create_space_response);
}

nvram_result_t trusty_delete_space(const struct nvram_device* device,
                                   uint32_t index,
                                   uint8_t* authorization_value,
                                   uint32_t authorization_value_size) {
  nvram::DeleteSpaceRequest delete_space_request;
  delete_space_request.index = index;
  if (!delete_space_request.authorization_value.Assign(
          authorization_value, authorization_value_size)) {
    return NV_RESULT_INTERNAL_ERROR;
  }
  nvram::DeleteSpaceResponse delete_space_response;
  return Execute<nvram::COMMAND_DELETE_SPACE>(
      device, std::move(delete_space_request), &delete_space_response);
}

nvram_result_t trusty_disable_create(const struct nvram_device* device) {
  nvram::DisableCreateRequest disable_create_request;
  nvram::DisableCreateResponse disable_create_response;
  return Execute<nvram::COMMAND_DISABLE_CREATE>(
      device, std::move(disable_create_request), &disable_create_response);
}

nvram_result_t trusty_write_space(const struct nvram_device* device,
                                  uint32_t index,
                                  const uint8_t* buffer,
                                  uint64_t buffer_size,
                                  uint8_t* authorization_value,
                                  uint32_t authorization_value_size) {
  nvram::WriteSpaceRequest write_space_request;
  write_space_request.index = index;
  if (!write_space_request.buffer.Assign(buffer, buffer_size) ||
      !write_space_request.authorization_value.Assign(
          authorization_value, authorization_value_size)) {
    return NV_RESULT_INTERNAL_ERROR;
  }
  nvram::WriteSpaceResponse write_space_response;
  return Execute<nvram::COMMAND_WRITE_SPACE>(
      device, std::move(write_space_request), &write_space_response);
}

nvram_result_t trusty_read_space(const struct nvram_device* device,
                                 uint32_t index,
                                 uint64_t num_bytes_to_read,
                                 uint8_t* authorization_value,
                                 uint32_t authorization_value_size,
                                 uint8_t* buffer,
                                 uint64_t* bytes_read) {
  nvram::ReadSpaceRequest read_space_request;
  read_space_request.index = index;
  if (!read_space_request.authorization_value.Assign(
          authorization_value, authorization_value_size)) {
    return NV_RESULT_INTERNAL_ERROR;
  }
  nvram::ReadSpaceResponse read_space_response;
  nvram_result_t result = Execute<nvram::COMMAND_READ_SPACE>(
      device, std::move(read_space_request), &read_space_response);
  *bytes_read = std::min(static_cast<size_t>(num_bytes_to_read),
                         read_space_response.buffer.size());
  memcpy(buffer, read_space_response.buffer.data(), *bytes_read);
  return result;
}

nvram_result_t trusty_enable_write_lock(const struct nvram_device* device,
                                        uint32_t index,
                                        uint8_t* authorization_value,
                                        uint32_t authorization_value_size) {
  nvram::LockSpaceWriteRequest lock_space_write_request;
  lock_space_write_request.index = index;
  if (!lock_space_write_request.authorization_value.Assign(
          authorization_value, authorization_value_size)) {
    return NV_RESULT_INTERNAL_ERROR;
  }
  nvram::LockSpaceWriteResponse lock_space_write_response;
  return Execute<nvram::COMMAND_LOCK_SPACE_WRITE>(
      device, std::move(lock_space_write_request), &lock_space_write_response);
}

nvram_result_t trusty_enable_read_lock(const struct nvram_device* device,
                                       uint32_t index,
                                       uint8_t* authorization_value,
                                       uint32_t authorization_value_size) {
  nvram::LockSpaceReadRequest lock_space_read_request;
  lock_space_read_request.index = index;
  if (!lock_space_read_request.authorization_value.Assign(
          authorization_value, authorization_value_size)) {
    return NV_RESULT_INTERNAL_ERROR;
  }
  nvram::LockSpaceReadResponse lock_space_read_response;
  return Execute<nvram::COMMAND_LOCK_SPACE_READ>(
      device, std::move(lock_space_read_request), &lock_space_read_response);
}

int trusty_nvram_device_close(struct hw_device_t* device) {
  delete reinterpret_cast<TrustyNvramDevice*>(device);
  return 0;
}

}  // extern "C"
}  // namespace

extern "C" int trusty_nvram_open(const hw_module_t* module,
                                 const char* device_id,
                                 hw_device_t** device_ptr) {
  if (strcmp(NVRAM_HARDWARE_DEVICE_ID, device_id) != 0) {
    return -EINVAL;
  }

  TrustyNvramDevice* trusty_nvram_device = new TrustyNvramDevice;
  struct nvram_device* device = &trusty_nvram_device->device;
  memset(device, 0, sizeof(struct nvram_device));

  device->common.tag = HARDWARE_DEVICE_TAG;
  device->common.version = NVRAM_DEVICE_API_VERSION_0_1;
  device->common.module = const_cast<hw_module_t *>(module);
  device->common.close = trusty_nvram_device_close;

  device->get_total_size_in_bytes = trusty_get_total_size_in_bytes;
  device->get_available_size_in_bytes = trusty_get_available_size_in_bytes;
  device->get_max_spaces = trusty_get_max_spaces;
  device->get_space_list = trusty_get_space_list;
  device->get_space_size = trusty_get_space_size;
  device->get_space_controls = trusty_get_space_controls;
  device->is_space_locked = trusty_is_space_locked;
  device->create_space = trusty_create_space;
  device->delete_space = trusty_delete_space;
  device->disable_create = trusty_disable_create;
  device->write_space = trusty_write_space;
  device->read_space = trusty_read_space;
  device->enable_write_lock = trusty_enable_write_lock;
  device->enable_read_lock = trusty_enable_read_lock;

  *device_ptr = reinterpret_cast<hw_device_t*>(device);
  return 0;
}
