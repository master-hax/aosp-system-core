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

extern "C" {
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
}  // extern "C"

#include <string>
#include <utility>

#include <android-base/macros.h>
#include <nvram/nvram_messages.h>

#include "nvram_ipc.h"

#define CHECK(condition)                                                   \
  do {                                                                     \
    if (!(condition)) {                                                    \
      fprintf(stderr, "CHECK failed at %s:%d: " #condition "\n", __FILE__, \
              __LINE__);                                                   \
      abort();                                                             \
    }                                                                      \
  } while (false)

using namespace nvram;

// Exit status codes. These are all negative as the positive ones are used for
// the RESULT_ codes.
enum StatusCode {
  kStatusInvalidArg = -1,
  kStatusConnectionFailed = -2,
  kStatusCommunicationError = -3,
  kStatusBadReply = -4,
};

// A table mapping control values to names.
struct {
  Control control;
  const char* name;
} kControlNameTable[] = {
    {CONTROL_PERSISTENT_WRITE_LOCK, "PERSISTENT_WRITE_LOCK"},
    {CONTROL_BOOT_WRITE_LOCK, "BOOT_WRITE_LOCK"},
    {CONTROL_BOOT_READ_LOCK, "BOOT_READ_LOCK"},
    {CONTROL_WRITE_AUTHORIZATION, "WRITE_AUTHORIZATION"},
    {CONTROL_READ_AUTHORIZATION, "READ_AUTHORIZATION"},
    {CONTROL_WRITE_EXTEND, "WRITE_EXTEND"},
};

bool ParseControl(const std::string& name, Control* control) {
  for (size_t i = 0; i < arraysize(kControlNameTable); ++i) {
    if (kControlNameTable[i].name == name) {
      *control = kControlNameTable[i].control;
      return true;
    }
  }

  return false;
}

bool ParseControlList(const std::string& list, List<Control>* controls) {
  bool result = true;
  size_t end = 0;
  size_t pos = 0;
  size_t control_count = 0;
  do {
    end = list.find(',', pos);
    Control control;
    if (ParseControl(list.substr(pos, end - pos), &control)) {
      CHECK(controls->Resize(control_count + 1));
      (*controls)[control_count] = control;
      ++control_count;
    } else {
      result = false;
    }
    pos = end + 1;
  } while (end != std::string::npos);

  return result;
}

bool FormatControl(uint32_t control, std::string* name) {
  for (size_t i = 0; i < arraysize(kControlNameTable); ++i) {
    if (kControlNameTable[i].control == control) {
      *name = kControlNameTable[i].name;
      return true;
    }
  }

  return false;
}

bool FormatControlList(const List<Control>& controls, std::string* list) {
  bool result = true;
  list->clear();
  for (uint32_t control : controls) {
    std::string control_name;
    if (FormatControl(control, &control_name)) {
      list->append(control_name);
      list->append(",");
    } else {
      result = false;
    }
  }

  // Strip trailing comma.
  if (!list->empty()) {
    list->resize(list->size() - 1);
  }
  return result;
}

template <Command command, typename RequestPayload, typename ResponsePayload>
int Execute(RequestPayload&& request_payload,
            ResponsePayload* response_payload) {
  Request request;
  request.get<Request_Payload>().Activate<command>() =
      std::move(request_payload);
  Response response;
  if (ExecuteRequest(request, &response)) {
    Result result = response.get<Response_Result>();
    if (result != RESULT_SUCCESS) {
      fprintf(stderr, "Request failed with result code: %u\n", result);
      return result;
    }

    ResponsePayload* response_payload_ptr =
        response.get<Response_Payload>().get<command>();
    if (!response_payload_ptr) {
      fprintf(stderr, "Missing response payload.\n");
      return kStatusBadReply;
    }
    *response_payload = std::move(*response_payload_ptr);

    return 0;
  }

  fprintf(stderr, "Failed to execute request.\n");
  return kStatusCommunicationError;
}

int HandleGetInfo(char* []) {
  GetInfoRequest request;
  GetInfoResponse response;
  int status = Execute<COMMAND_GET_INFO>(std::move(request), &response);
  if (status != 0) {
    return status;
  }

  std::string space_list;
  for (uint32_t space_index : response.get<GetInfoResponse_SpaceList>()) {
    space_list += std::to_string(space_index);
    space_list += ",";
  }
  if (!space_list.empty()) {
    space_list.resize(space_list.size() - 1);
  }

  printf(
      "total_size: %lu\n"
      "available_size: %lu\n"
      "max_spaces: %u\n"
      "space_list: %s\n",
      response.get<GetInfoResponse_TotalSize>(),
      response.get<GetInfoResponse_AvailableSize>(),
      response.get<GetInfoResponse_MaxSpaces>(), space_list.c_str());

  return 0;
}

int HandleCreateSpace(char* args[]) {
  CreateSpaceRequest request;
  request.get<CreateSpaceRequest_Index>() = std::stoul(args[0], nullptr, 0);
  request.get<CreateSpaceRequest_Size>() = std::stoul(args[1], nullptr, 0);
  if (!ParseControlList(args[2], &request.get<CreateSpaceRequest_Controls>())) {
    fprintf(stderr, "Failed to parse control list\n");
    return kStatusInvalidArg;
  }
  CHECK(request.get<CreateSpaceRequest_AuthorizationValue>().Assign(
      args[3], strlen(args[3])));

  CreateSpaceResponse response;
  return Execute<COMMAND_CREATE_SPACE>(std::move(request), &response);
}

int HandleGetSpaceInfo(char* args[]) {
  GetSpaceInfoRequest request;
  request.get<GetSpaceInfoRequest_Index>() = std::stoul(args[0], nullptr, 0);
  GetSpaceInfoResponse response;
  int status = Execute<COMMAND_GET_SPACE_INFO>(std::move(request), &response);
  if (status != 0) {
    return status;
  }

  std::string controls;
  FormatControlList(response.get<GetSpaceInfoResponse_Controls>(), &controls);
  printf(
      "size: %lu\n"
      "controls: %s\n"
      "read_locked: %d\n"
      "write_locked: %d\n",
      response.get<GetSpaceInfoResponse_Size>(), controls.c_str(),
      response.get<GetSpaceInfoResponse_ReadLocked>(),
      response.get<GetSpaceInfoResponse_WriteLocked>());

  return 0;
}

int HandleDeleteSpace(char* args[]) {
  DeleteSpaceRequest request;
  request.get<DeleteSpaceRequest_Index>() = std::stoul(args[0], nullptr, 0);
  CHECK(request.get<DeleteSpaceRequest_AuthorizationValue>().Assign(
      args[1], strlen(args[1])));
  DeleteSpaceResponse response;
  return Execute<COMMAND_DELETE_SPACE>(std::move(request), &response);
}

int HandleDisableCreate(char* []) {
  DisableCreateRequest request;
  DisableCreateResponse response;
  return Execute<COMMAND_DISABLE_CREATE>(std::move(request), &response);
}

int HandleWriteSpace(char* args[]) {
  WriteSpaceRequest request;
  request.get<WriteSpaceRequest_Index>() = std::stoul(args[0], nullptr, 0);
  CHECK(
      request.get<WriteSpaceRequest_Buffer>().Assign(args[1], strlen(args[1])));
  CHECK(request.get<WriteSpaceRequest_AuthorizationValue>().Assign(
      args[2], strlen(args[2])));
  WriteSpaceResponse response;
  return Execute<COMMAND_WRITE_SPACE>(std::move(request), &response);
}

int HandleReadSpace(char* args[]) {
  ReadSpaceRequest request;
  request.get<ReadSpaceRequest_Index>() = std::stoul(args[0], nullptr, 0);
  CHECK(request.get<ReadSpaceRequest_AuthorizationValue>().Assign(
      args[1], strlen(args[1])));
  ReadSpaceResponse response;
  int status = Execute<COMMAND_READ_SPACE>(std::move(request), &response);
  if (status != 0) {
    return status;
  }

  Blob& buffer = response.get<ReadSpaceResponse_Buffer>();
  fwrite(buffer.data(), sizeof(uint8_t), buffer.size(), stdout);
  return 0;
}

int HandleLockSpaceWrite(char* args[]) {
  LockSpaceWriteRequest request;
  request.get<LockSpaceWriteRequest_Index>() = std::stoul(args[0], nullptr, 0);
  CHECK(request.get<LockSpaceWriteRequest_AuthorizationValue>().Assign(
      args[1], strlen(args[1])));
  LockSpaceWriteResponse response;
  return Execute<COMMAND_LOCK_SPACE_WRITE>(std::move(request), &response);
}

int HandleLockSpaceRead(char* args[]) {
  LockSpaceReadRequest request;
  request.get<LockSpaceReadRequest_Index>() = std::stoul(args[0], nullptr, 0);
  CHECK(request.get<LockSpaceReadRequest_AuthorizationValue>().Assign(
      reinterpret_cast<uint8_t*>(args[1]), strlen(args[1])));
  LockSpaceReadResponse response;
  return Execute<COMMAND_LOCK_SPACE_READ>(std::move(request), &response);
}

struct CommandHandler {
  const char* name;
  const char* params_desc;
  int nparams;
  int (*run)(char* args[]);
};

struct CommandHandler kCommandHandlers[] = {
    {"get_info", "", 0, &HandleGetInfo},
    {"create_space", "<index> <size> <controls> <auth>", 4, &HandleCreateSpace},
    {"get_space_info", "<index>", 1, &HandleGetSpaceInfo},
    {"delete_space", "<index> <auth>", 2, &HandleDeleteSpace},
    {"disable_create", "", 0, &HandleDisableCreate},
    {"write_space", "<index> <data> <auth>", 3, &HandleWriteSpace},
    {"read_space", "<index> <auth>", 2, &HandleReadSpace},
    {"lock_space_write", "<index> <auth>", 2, &HandleLockSpaceWrite},
    {"lock_space_read", "<index> <auth>", 2, &HandleLockSpaceRead},
};

int main(int argc, char* argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <command> <command-args>\n", argv[0]);
    fprintf(stderr, "Valid commands are:\n");
    for (const CommandHandler& handler : kCommandHandlers) {
      fprintf(stderr, "  %s %s\n", handler.name, handler.params_desc);
    }
    return kStatusInvalidArg;
  }

  const struct CommandHandler* cmd = NULL;
  for (size_t i = 0; i < arraysize(kCommandHandlers); ++i) {
    if (strcmp(kCommandHandlers[i].name, argv[1]) == 0) {
      cmd = &kCommandHandlers[i];
    }
  }

  if (!cmd) {
    fprintf(stderr, "Bad command: %s\n", argv[1]);
    return kStatusInvalidArg;
  }

  if (argc - 2 != cmd->nparams) {
    fprintf(stderr, "Command %s takes %d parameters, %d given.\n", argv[1],
            cmd->nparams, argc - 2);
    return kStatusInvalidArg;
  }

  if (!Connect()) {
    fprintf(stderr, "Failed to open trusty connection.\n");
    return kStatusConnectionFailed;
  }

  int status = cmd->run(argv + 2);
  Disconnect();

  return status;
}
