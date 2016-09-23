// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TEST_EMBEDDED_TEST_SERVER_ANDROID_EMBEDDED_TEST_SERVER_ANDROID_H_
#define NET_TEST_EMBEDDED_TEST_SERVER_ANDROID_EMBEDDED_TEST_SERVER_ANDROID_H_

#include <jni.h>

#include "base/android/jni_weak_ref.h"
#include "base/android/scoped_java_ref.h"
#include "base/macros.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"

namespace net {
namespace test_server {

// The C++ side of the Java EmbeddedTestServer.
class EmbeddedTestServerAndroid {
 public:
  EmbeddedTestServerAndroid(JNIEnv* env,
                            const base::android::JavaRef<jobject>& obj);
  ~EmbeddedTestServerAndroid();

  void Destroy(JNIEnv* env, const base::android::JavaParamRef<jobject>& obj);

  jboolean Start(JNIEnv* env, const base::android::JavaParamRef<jobject>& jobj);

  jboolean ShutdownAndWaitUntilComplete(
      JNIEnv* env,
      const base::android::JavaParamRef<jobject>& jobj);

  base::android::ScopedJavaLocalRef<jstring> GetURL(
      JNIEnv* jenv,
      const base::android::JavaParamRef<jobject>& jobj,
      const base::android::JavaParamRef<jstring>& jrelative_url) const;

  void AddDefaultHandlers(
      JNIEnv* jenv,
      const base::android::JavaParamRef<jobject>& jobj,
      const base::android::JavaParamRef<jstring>& jdirectory_path);

  void ServeFilesFromDirectory(
      JNIEnv* env,
      const base::android::JavaParamRef<jobject>& jobj,
      const base::android::JavaParamRef<jstring>& jdirectory_path);

  static bool RegisterEmbeddedTestServerAndroid(JNIEnv* env);

 private:
  JavaObjectWeakGlobalRef weak_java_server_;

  EmbeddedTestServer test_server_;

  DISALLOW_COPY_AND_ASSIGN(EmbeddedTestServerAndroid);
};

}  // namespace test_server
}  // namespace net

#endif  // NET_TEST_EMBEDDED_TEST_SERVER_ANDROID_EMBEDDED_TEST_SERVER_ANDROID_H_
