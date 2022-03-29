/*
 * Copyright (C) 2021 The Android Open Source Project
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

interface ITestService {
    const @utf8InCpp String PORT = "com.android.trusty.aidl.test.service";

    void error(in int err);
    int add(in int a, in int b);
    int hash(in byte[] buf);

    int hash_payload();
    void rand_payload(in int seed);
    void add2_payload();
}
