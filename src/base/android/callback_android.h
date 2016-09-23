// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ANDROID_CALLBACK_ANDROID_H_
#define BASE_ANDROID_CALLBACK_ANDROID_H_

#include <jni.h>

#include "base/android/scoped_java_ref.h"
#include "base/base_export.h"

namespace base {
namespace android {

// Runs the given |callback| with the specified |arg|.
void BASE_EXPORT RunCallbackAndroid(const JavaRef<jobject>& callback,
                                    const JavaRef<jobject>& arg);

// Runs the given |callback| with the specified |arg|.
void BASE_EXPORT RunCallbackAndroid(const JavaRef<jobject>& callback,
                                    bool arg);

// Runs the given |callback| with the specified |arg|.
void BASE_EXPORT RunCallbackAndroid(const JavaRef<jobject>& callback, int arg);

}  // namespace android
}  // namespace base

#endif  // BASE_ANDROID_CALLBACK_ANDROID_H_
