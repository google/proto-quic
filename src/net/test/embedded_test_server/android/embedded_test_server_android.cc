// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/embedded_test_server/android/embedded_test_server_android.h"

#include "base/android/jni_string.h"
#include "base/android/scoped_java_ref.h"
#include "base/bind.h"
#include "base/files/file_path.h"
#include "base/test/test_support_android.h"
#include "base/trace_event/trace_event.h"
#include "net/test/jni/EmbeddedTestServerImpl_jni.h"

using base::android::JavaParamRef;
using base::android::JavaRef;

namespace net {
namespace test_server {

EmbeddedTestServerAndroid::EmbeddedTestServerAndroid(
    JNIEnv* env,
    const JavaRef<jobject>& jobj)
    : weak_java_server_(env, jobj), test_server_() {
  Java_EmbeddedTestServerImpl_setNativePtr(env, jobj,
                                           reinterpret_cast<intptr_t>(this));
}

EmbeddedTestServerAndroid::~EmbeddedTestServerAndroid() {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_EmbeddedTestServerImpl_clearNativePtr(env, weak_java_server_.get(env));
}

jboolean EmbeddedTestServerAndroid::Start(JNIEnv* env,
                                          const JavaParamRef<jobject>& jobj) {
  return test_server_.Start();
}

jboolean EmbeddedTestServerAndroid::ShutdownAndWaitUntilComplete(
    JNIEnv* env,
    const JavaParamRef<jobject>& jobj) {
  return test_server_.ShutdownAndWaitUntilComplete();
}

base::android::ScopedJavaLocalRef<jstring> EmbeddedTestServerAndroid::GetURL(
    JNIEnv* env,
    const JavaParamRef<jobject>& jobj,
    const JavaParamRef<jstring>& jrelative_url) const {
  const GURL gurl(test_server_.GetURL(
      base::android::ConvertJavaStringToUTF8(env, jrelative_url)));
  return base::android::ConvertUTF8ToJavaString(env, gurl.spec());
}

void EmbeddedTestServerAndroid::AddDefaultHandlers(
    JNIEnv* env,
    const JavaParamRef<jobject>& jobj,
    const JavaParamRef<jstring>& jdirectory_path) {
  const base::FilePath directory(
      base::android::ConvertJavaStringToUTF8(env, jdirectory_path));
  test_server_.AddDefaultHandlers(directory);
}

void EmbeddedTestServerAndroid::ServeFilesFromDirectory(
    JNIEnv* env,
    const JavaParamRef<jobject>& jobj,
    const JavaParamRef<jstring>& jdirectory_path) {
  const base::FilePath directory(
      base::android::ConvertJavaStringToUTF8(env, jdirectory_path));
  test_server_.ServeFilesFromDirectory(directory);
}

void EmbeddedTestServerAndroid::Destroy(JNIEnv* env,
                                        const JavaParamRef<jobject>& jobj) {
  delete this;
}

static void Init(JNIEnv* env,
                 const JavaParamRef<jobject>& jobj,
                 const JavaParamRef<jstring>& jtest_data_dir) {
  TRACE_EVENT0("native", "EmbeddedTestServerAndroid::Init");
  base::FilePath test_data_dir(
      base::android::ConvertJavaStringToUTF8(env, jtest_data_dir));
  base::InitAndroidTestPaths(test_data_dir);
  new EmbeddedTestServerAndroid(env, jobj);
}

// static
bool EmbeddedTestServerAndroid::RegisterEmbeddedTestServerAndroid(JNIEnv* env) {
  return RegisterNativesImpl(env);
}

}  // namespace test_server
}  // namespace net
