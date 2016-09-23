// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ANDROID_JAVA_HANDLER_THREAD_FOR_TESTING_H_
#define BASE_ANDROID_JAVA_HANDLER_THREAD_FOR_TESTING_H_

#include "base/android/java_handler_thread.h"
#include "base/android/java_message_handler_factory.h"
#include "base/message_loop/message_loop.h"
#include "base/test/android/test_system_message_handler_link_android.h"

namespace base {

namespace android {

// Factory class for creating a custom Java-side message handler.
// The implementation of this class creates a test-only message handler, so to
// avoid including the code of that message handler in production code we use a
// factory to create it instead of directly creating it from MessagePumpForUI.
class TestJavaMessageHandlerFactory : public JavaMessageHandlerFactory {
  base::android::ScopedJavaLocalRef<jobject> CreateMessageHandler(
      JNIEnv* env,
      base::MessagePump::Delegate* delegate,
      MessagePumpForUI* message_pump,
      WaitableEvent* test_done_event) override;
};

// Test-version of JavaHandlerThread, we need this class to start and stop the
// message loop of the new thread in a different way than JavaHandlerThread
// does.
// This is partly because we need to create a test-only java-side message
// handler to back the native message loop, and partly because our tests cause
// the corresponding message pump to abort which means it won't reach its idle
// work state and thus can't quit when idle. We here stop the pump more abruptly
// instead.
class JavaHandlerThreadForTesting : public JavaHandlerThread {
 public:
  JavaHandlerThreadForTesting(const char* name,
                              base::WaitableEvent* test_done_event);
  ~JavaHandlerThreadForTesting() override;

  void StartMessageLoop() override;
  void StopMessageLoop() override;

 private:
  std::unique_ptr<JavaMessageHandlerFactory> message_handler_factory_;
  base::WaitableEvent* test_done_event_;
};

}  // namespace android
}  // namespace base

#endif  // BASE_ANDROID_JAVA_HANDLER_THREAD_FOR_TESTING_H_
