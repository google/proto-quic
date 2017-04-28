// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/statistics_recorder.h"
#include "base/test/launcher/unit_test_launcher.h"
#include "build/build_config.h"
#include "crypto/nss_util.h"
#include "net/socket/client_socket_pool_base.h"
#include "net/socket/ssl_server_socket.h"
#include "net/test/net_test_suite.h"
#include "url/url_features.h"

#if defined(OS_ANDROID)
#include "base/android/jni_android.h"
#include "base/android/jni_registrar.h"
#include "net/android/dummy_spnego_authenticator.h"
#include "net/android/net_jni_registrar.h"
#endif

#if !defined(OS_ANDROID) && !defined(OS_IOS)
//#include "mojo/edk/embedder/embedder.h"  // nogncheck
#endif

using net::internal::ClientSocketPoolBaseHelper;

int main(int argc, char** argv) {
  // Record histograms, so we can get histograms data in tests.
  base::StatisticsRecorder::Initialize();

#if defined(OS_ANDROID)
  const base::android::RegistrationMethod kNetTestRegisteredMethods[] = {
    {"DummySpnegoAuthenticator",
     net::android::DummySpnegoAuthenticator::RegisterJni},
    {"NetAndroid", net::android::RegisterJni},
  };

  // Register JNI bindings for android. Doing it early as the test suite setup
  // may initiate a call to Java.
  base::android::RegisterNativeMethods(
      base::android::AttachCurrentThread(),
      kNetTestRegisteredMethods,
      arraysize(kNetTestRegisteredMethods));
#endif

  NetTestSuite test_suite(argc, argv);
  ClientSocketPoolBaseHelper::set_connect_backup_jobs_enabled(false);

#if !defined(OS_ANDROID) && !defined(OS_IOS)
  //  mojo::edk::Init();
#endif

  return base::LaunchUnitTests(
      argc, argv, base::Bind(&NetTestSuite::Run,
                             base::Unretained(&test_suite)));
}
