// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_ANDROID_NET_JNI_REGISTRAR_H_
#define NET_ANDROID_NET_JNI_REGISTRAR_H_

#include <jni.h>

#include "net/base/net_export.h"

namespace net {
namespace android {

// Register all JNI bindings necessary for net.
NET_EXPORT bool RegisterJni(JNIEnv* env);

}  // namespace android
}  // namespace net

#endif  // NET_ANDROID_NET_JNI_REGISTRAR_H_
