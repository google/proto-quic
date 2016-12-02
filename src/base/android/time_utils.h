// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ANDROID_TIME_UTILS_H_
#define BASE_ANDROID_TIME_UTILS_H_

#include <jni.h>

namespace base {
namespace android {

bool RegisterTimeUtils(JNIEnv* env);

}  // namespace android
}  // namespace base

#endif  // BASE_ANDROID_TIME_UTILS_H_
