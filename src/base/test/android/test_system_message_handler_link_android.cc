// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/android/test_system_message_handler_link_android.h"

#include "base/message_loop/message_pump_android.h"
#include "base/synchronization/waitable_event.h"
#include "jni/TestSystemMessageHandler_jni.h"

namespace base {
namespace android {

base::android::ScopedJavaLocalRef<jobject>
TestSystemMessageHandlerLink::CreateTestSystemMessageHandler(
    JNIEnv* env,
    base::MessagePump::Delegate* delegate,
    MessagePumpForUI* message_pump,
    WaitableEvent* test_done_event) {
  return Java_TestSystemMessageHandler_create(
      env, reinterpret_cast<intptr_t>(delegate),
      reinterpret_cast<intptr_t>(message_pump),
      reinterpret_cast<intptr_t>(test_done_event));
}

bool TestSystemMessageHandlerLink::RegisterJNI(JNIEnv* env) {
  return RegisterNativesImpl(env);
}

static void NotifyTestDone(JNIEnv* env,
                           const base::android::JavaParamRef<jclass>& jcaller,
                           jlong native_waitable_test_event) {
  WaitableEvent* event =
      reinterpret_cast<WaitableEvent*>(native_waitable_test_event);
  DCHECK(event);
  event->Signal();
}

}  // namespace android
}  // namespace base
