// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/android/net_test_jni_onload.h"

#include "base/android/base_jni_onload.h"
#include "base/android/base_jni_registrar.h"
#include "base/android/jni_android.h"
#include "base/bind.h"
#include "net/test/embedded_test_server/android/embedded_test_server_android.h"

namespace net {
namespace test {

namespace {

bool RegisterJNI(JNIEnv* env) {
  return net::test_server::EmbeddedTestServerAndroid::
      RegisterEmbeddedTestServerAndroid(env);
}

}  // namesapce

bool OnJNIOnLoadRegisterJNI(JNIEnv* env) {
  return base::android::OnJNIOnLoadRegisterJNI(env) &&
         base::android::RegisterJni(env) && RegisterJNI(env);
}

bool OnJNIOnLoadInit() {
  return base::android::OnJNIOnLoadInit();
}

}  // namespace test
}  // namespace net
