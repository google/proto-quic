// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "base/android/jni_array.h"
#include "base/logging.h"
#include "base/posix/global_descriptors.h"
#include "jni/MainRunner_jni.h"
#include "testing/android/native_test/native_test_util.h"

extern int main(int argc, char** argv);

namespace testing {
namespace android {

bool RegisterMainRunnerJni(JNIEnv* env) {
  return RegisterNativesImpl(env);
}

static jint RunMain(
    JNIEnv* env,
    const base::android::JavaParamRef<jclass>& jcaller,
    const base::android::JavaParamRef<jobjectArray>& command_line,
    const base::android::JavaParamRef<jintArray>& fds_to_map_keys,
    const base::android::JavaParamRef<jintArray>& fds_to_map_fds) {
  // Guards against process being reused.
  // In most cases, running main again will cause problems (static variables,
  // singletons, lazy instances won't be in the same state as a clean run).
  static bool alreadyRun = false;
  CHECK(!alreadyRun);
  alreadyRun = true;

  std::vector<int> keys;
  base::android::JavaIntArrayToIntVector(env, fds_to_map_keys, &keys);
  std::vector<int> fds;
  base::android::JavaIntArrayToIntVector(env, fds_to_map_fds, &fds);
  CHECK_EQ(keys.size(), fds.size());

  for (size_t i = 0; i < keys.size(); i++) {
    base::GlobalDescriptors::GetInstance()->Set(keys[i], fds[i]);
  }

  std::vector<std::string> cpp_command_line;
  AppendJavaStringArrayToStringVector(env, command_line, &cpp_command_line);

  std::vector<char*> argv;
  int argc = ArgsToArgv(cpp_command_line, &argv);
  return main(argc, &argv[0]);
}

}  // namespace android
}  // namespace testing
