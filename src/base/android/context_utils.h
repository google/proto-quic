// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ANDROID_CONTEXT_UTILS_H_
#define BASE_ANDROID_CONTEXT_UTILS_H_

#include <jni.h>

#include "base/android/scoped_java_ref.h"
#include "base/base_export.h"

namespace base {
namespace android {

// Gets a global ref to the application context set with
// InitApplicationContext(). Ownership is retained by the function - the caller
// must NOT release it.
BASE_EXPORT jobject GetApplicationContext();

// Initialize the global application context object.
// Either this or the Java equivalent ContextUtils.initApplicationContext must
// be called once during startup. JNI bindings must have been initialized, as
// the context is stored on both sides.
BASE_EXPORT void InitApplicationContext(
    JNIEnv* env,
    const base::android::JavaRef<jobject>& context);

bool RegisterContextUtils(JNIEnv* env);

}  // namespace android
}  // namespace base

#endif  // BASE_ANDROID_CONTEXT_UTILS_H_
