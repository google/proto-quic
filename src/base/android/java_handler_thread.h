// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ANDROID_JAVA_HANDLER_THREAD_H_
#define BASE_ANDROID_JAVA_HANDLER_THREAD_H_

#include <jni.h>

#include <memory>

#include "base/android/scoped_java_ref.h"

namespace base {

class MessageLoop;

namespace android {

// A Java Thread with a native message loop. To run tasks, post them
// to the message loop and they will be scheduled along with Java tasks
// on the thread.
// This is useful for callbacks where the receiver expects a thread
// with a prepared Looper.
class BASE_EXPORT JavaHandlerThread {
 public:
  // Create new thread.
  explicit JavaHandlerThread(const char* name);
  // Wrap and connect to an existing JavaHandlerThread.
  // |obj| is an instance of JavaHandlerThread.
  explicit JavaHandlerThread(
      const base::android::ScopedJavaLocalRef<jobject>& obj);
  virtual ~JavaHandlerThread();

  base::MessageLoop* message_loop() const { return message_loop_.get(); }
  void Start();
  void Stop();

  // Called from java on the newly created thread.
  // Start() will not return before this methods has finished.
  void InitializeThread(JNIEnv* env,
                        const JavaParamRef<jobject>& obj,
                        jlong event);
  void StopThread(JNIEnv* env,
                  const JavaParamRef<jobject>& obj,
                  jlong event);

  virtual void StartMessageLoop();
  virtual void StopMessageLoop();

  static bool RegisterBindings(JNIEnv* env);

 protected:
  std::unique_ptr<base::MessageLoop> message_loop_;

 private:
  ScopedJavaGlobalRef<jobject> java_thread_;
};

}  // namespace android
}  // namespace base

#endif  // BASE_ANDROID_JAVA_HANDLER_THREAD_H_
