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

#[cfg(test)]
mod tests {
    //use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
    //use android_hardware_security_see::binder;
    //use rpcbinder::{FileDescriptorTransportMode, RpcSession};
    use trusty::{self, DEFAULT_DEVICE};
    //use trusty_binder;
    //////////
    //use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
    //use rpcbinder::RpcSessionRef;
    use binderRpcTestIface::aidl::IBinderRpcTest::IBinderRpcTest;
    use rpcbinder::RpcSession;

    //const RUST_SERVICE_PORT: &str = "com.android.trusty.rust.hwcryptohal.V1";
    //const RUST_SERVICE_PORT: &str = "com.android.frameworks.stats.trusty.test.relayer.istats_setter";
    const RUST_SERVICE_PORT: &str = "com.android.trusty.rust.binderRpcTestService.V1";

    #[test]
    fn connect_test_value() {
        // 3 different ways of connecting to the RPC server (2nd and 3rd are proabbly prefered over)
        // the second one. The part that still needs to be figured out is that some of the code I am
        // using is not intended for vendor code.
        // 1st way using a method similar to setup_vsock_client but on the RpcSessionRef object directly.
        /*let binder_obj = RpcSessionRef::setup_trusty_client::<dyn IBinderRpcTest>(DEFAULT_DEVICE, RUST_SERVICE_PORT);
        assert!((binder_obj).is_ok(), "couldn't create binder object");*/
        //////////////////////////
        // 2nd way using a wrapper on the TrustyBinderRpc libraries.
        /*let binder_obj = trusty_binder::connect_rpc_server(DEFAULT_DEVICE, RUST_SERVICE_PORT);
        assert!(binder_obj.is_ok(), "couldn't create bidner object");*/
        //////////////////////////
        // 3rd way using a method similar to setup_vsock_client, but creating a trusty connection
        // first on the RpcSessionobject.
        let session = RpcSession::new_trusty(DEFAULT_DEVICE, RUST_SERVICE_PORT);
        let binder_obj = session.session_to_handle::<dyn IBinderRpcTest>();
        assert!(binder_obj.is_ok(), "couldn't create binder object");
    }
}
