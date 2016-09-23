// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/bind.h"
#include "base/test/launcher/unit_test_launcher.h"
#include "base/test/test_suite.h"
#include "build/build_config.h"

#if defined(OS_ANDROID)
#include "base/android/jni_android.h"
#include "base/test/android/test_system_message_handler_link_android.h"
#endif  // defined(OS_ANDROID)

int main(int argc, char** argv) {
#if defined(OS_ANDROID)
  base::android::TestSystemMessageHandlerLink::RegisterJNI(
      base::android::AttachCurrentThread());
#endif  // defined(OS_ANDROID)

  base::TestSuite test_suite(argc, argv);
  return base::LaunchUnitTests(
      argc, argv,
      base::Bind(&base::TestSuite::Run, base::Unretained(&test_suite)));
}
