// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/android/net_test_jni_onload.h"

#include "base/android/base_jni_onload.h"
#include "base/android/base_jni_registrar.h"
#include "base/bind.h"
#include "net/test/embedded_test_server/android/embedded_test_server_android.h"

namespace net {
namespace test {

namespace {

bool RegisterJNI(JNIEnv* env) {
  return net::test_server::EmbeddedTestServerAndroid::
      RegisterEmbeddedTestServerAndroid(env);
}

bool Init() {
  return true;
}

}  // namesapce

bool OnJNIOnLoadRegisterJNI(JavaVM* vm) {
  std::vector<base::android::RegisterCallback> register_callbacks;
  register_callbacks.push_back(base::Bind(&RegisterJNI));
  register_callbacks.push_back(base::Bind(&base::android::RegisterJni));
  return base::android::OnJNIOnLoadRegisterJNI(vm, register_callbacks);
}

bool OnJNIOnLoadInit() {
  std::vector<base::android::InitCallback> init_callbacks;
  init_callbacks.push_back(base::Bind(&Init));
  return base::android::OnJNIOnLoadInit(init_callbacks);
}

}  // namespace test
}  // namespace net
