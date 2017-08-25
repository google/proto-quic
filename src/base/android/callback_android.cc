// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/callback_android.h"

#include "base/android/jni_array.h"
#include "base/android/scoped_java_ref.h"
#include "jni/Callback_jni.h"

namespace base {
namespace android {

void RunCallbackAndroid(const JavaRef<jobject>& callback,
                        const JavaRef<jobject>& arg) {
  Java_Callback_onResultFromNativeV_JLO(base::android::AttachCurrentThread(),
                                        callback, arg);
}

void RunCallbackAndroid(const JavaRef<jobject>& callback, bool arg) {
  Java_Callback_onResultFromNativeV_Z(base::android::AttachCurrentThread(),
                                      callback, static_cast<jboolean>(arg));
}

void RunCallbackAndroid(const JavaRef<jobject>& callback, int arg) {
  Java_Callback_onResultFromNativeV_I(base::android::AttachCurrentThread(),
                                      callback, arg);
}

void RunCallbackAndroid(const JavaRef<jobject>& callback,
                        const std::vector<uint8_t>& arg) {
  JNIEnv* env = base::android::AttachCurrentThread();
  base::android::ScopedJavaLocalRef<jbyteArray> j_bytes =
      base::android::ToJavaByteArray(env, arg);
  Java_Callback_onResultFromNativeV_AB(env, callback, j_bytes);
}

}  // namespace android
}  // namespace base
