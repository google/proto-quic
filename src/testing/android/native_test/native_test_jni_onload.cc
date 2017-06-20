// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/base_jni_onload.h"
#include "base/android/jni_android.h"
#include "base/android/library_loader/library_loader_hooks.h"
#include "base/bind.h"
#include "testing/android/native_test/native_test_launcher.h"

namespace {

bool RegisterJNI(JNIEnv *env) {
  return testing::android::RegisterNativeTestJNI(env);
}

bool NativeInit() {
  if (!base::android::OnJNIOnLoadInit())
    return false;
  testing::android::InstallHandlers();
  return true;
}

}  // namespace


// This is called by the VM when the shared library is first loaded.
JNI_EXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
  base::android::InitVM(vm);
  JNIEnv* env = base::android::AttachCurrentThread();
  if (!RegisterJNI(env) || !NativeInit()) {
    return -1;
  }
  return JNI_VERSION_1_4;
}
