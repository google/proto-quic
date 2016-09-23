// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEST_SYSTEM_MESSAGE_HANDLER_LINK_ANDROID_H
#define BASE_TEST_SYSTEM_MESSAGE_HANDLER_LINK_ANDROID_H

#include <jni.h>

#include "base/android/scoped_java_ref.h"
#include "base/message_loop/message_pump.h"

namespace base {

class MessagePumpForUI;
class WaitableEvent;

namespace android {
class TestJavaMessageHandlerFactory;

// This provides a link to (a way to create) the java-side
// TestSystemMessageHandler class.
class TestSystemMessageHandlerLink {
 public:
  static bool RegisterJNI(JNIEnv* env);

 private:
  friend class base::android::TestJavaMessageHandlerFactory;

  TestSystemMessageHandlerLink() = delete;
  ~TestSystemMessageHandlerLink() = delete;

  static base::android::ScopedJavaLocalRef<jobject>
  CreateTestSystemMessageHandler(JNIEnv* env,
                                 base::MessagePump::Delegate* delegate,
                                 MessagePumpForUI* message_pump,
                                 WaitableEvent* test_done_event);
};

}  // namespace android
}  // namespace base

#endif  // BASE_TEST_SYSTEM_MESSAGE_HANDLER_LINK_ANDROID_H
