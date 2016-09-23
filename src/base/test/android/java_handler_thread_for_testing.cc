// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/android/java_handler_thread_for_testing.h"

#include "base/message_loop/message_loop.h"

namespace base {
namespace android {

base::android::ScopedJavaLocalRef<jobject>
TestJavaMessageHandlerFactory::CreateMessageHandler(
    JNIEnv* env,
    base::MessagePump::Delegate* delegate,
    MessagePumpForUI* message_pump,
    WaitableEvent* test_done_event) {
  return TestSystemMessageHandlerLink::CreateTestSystemMessageHandler(
      env, delegate, message_pump, test_done_event);
}

JavaHandlerThreadForTesting::JavaHandlerThreadForTesting(
    const char* name,
    base::WaitableEvent* test_done_event)
    : JavaHandlerThread(name),
      message_handler_factory_(new TestJavaMessageHandlerFactory()),
      test_done_event_(test_done_event) {}

JavaHandlerThreadForTesting::~JavaHandlerThreadForTesting() = default;

void JavaHandlerThreadForTesting::StartMessageLoop() {
  static_cast<MessageLoopForUI*>(message_loop_.get())
      ->StartForTesting(
          message_handler_factory_.get(),
          reinterpret_cast<base::WaitableEvent*>(test_done_event_));
}

void JavaHandlerThreadForTesting::StopMessageLoop() {
  // Instead of calling MessageLoop::QuitWhenIdle here we call
  // MessageLoop::QuitNow. This is because QuitWhenIdle will have no effect on
  // the message loop after MessageLoop::Abort has been called (which should
  // have happened at this point).
  static_cast<MessageLoopForUI*>(message_loop_.get())->QuitNow();
  // The message loop must be destroyed on the thread it is attached to.
  message_loop_.reset();
}

}  // namespace base
}  // namespace android
