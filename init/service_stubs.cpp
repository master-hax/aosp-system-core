/*
 * Copyright (C) 2019 The Android Open Source Project
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

// first stage init do nothing service stub

#include "service.h"

#include <memory>
#include <string>
#include <vector>

#include "result.h"

namespace android {
namespace init {

ServiceList::ServiceList() {}

ServiceList& ServiceList::GetInstance() {
    static ServiceList instance;
    return instance;
}

void ServiceList::AddService(std::unique_ptr<Service>) {}

void ServiceList::MarkServicesUpdate() {}

std::unique_ptr<Service> Service::MakeTemporaryOneshotService(const std::vector<std::string>&) {
    return nullptr;
}

void Service::Reset() {}

void Service::Stop() {}

void Service::Restart() {}

Result<Success> Service::ExecStart() {
    return Error() << "No services in first stage init";
}

Result<Success> Service::Start() {
    return Error() << "No services in first stage init";
}

Result<Success> Service::StartIfNotDisabled() {
    return Error() << "No services in first stage init";
}

Result<Success> Service::Enable() {
    return Error() << "No services in first stage init";
}

Result<Success> ServiceParser::ParseSection(std::vector<std::string>&&, const std::string&, int) {
    return Success();
}

Result<Success> ServiceParser::ParseLineSection(std::vector<std::string>&&, int) {
    return Success();
}

Result<Success> ServiceParser::EndSection() {
    return Success();
}

}  // namespace init
}  // namespace android
