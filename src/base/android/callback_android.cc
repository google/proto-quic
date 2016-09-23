// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/callback_android.h"

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

}  // namespace android
}  // namespace base
