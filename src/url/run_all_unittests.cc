// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "base/bind.h"
#include "base/message_loop/message_loop.h"
#include "base/test/launcher/unit_test_launcher.h"
#include "base/test/test_io_thread.h"
#include "base/test/test_suite.h"
#include "build/build_config.h"

#if !defined(OS_IOS)
#include "mojo/edk/embedder/embedder.h"  // nogncheck
#include "mojo/edk/test/scoped_ipc_support.h"  // nogncheck
#endif

int main(int argc, char** argv) {
  base::TestSuite test_suite(argc, argv);

#if !defined(OS_IOS)
  mojo::edk::Init();
  base::TestIOThread test_io_thread(base::TestIOThread::kAutoStart);
  std::unique_ptr<mojo::edk::test::ScopedIPCSupport> ipc_support;
  ipc_support.reset(
      new mojo::edk::test::ScopedIPCSupport(test_io_thread.task_runner()));
#endif

  return base::LaunchUnitTests(
      argc, argv,
      base::Bind(&base::TestSuite::Run, base::Unretained(&test_suite)));
}
