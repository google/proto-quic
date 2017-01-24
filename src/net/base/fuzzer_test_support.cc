// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/at_exit.h"
#include "base/i18n/icu_util.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/metrics/statistics_recorder.h"

namespace {

// Set up globals that a number of network tests use.
//
// Note that in general static initializers are not allowed, however this is
// just being used by test code.
struct InitGlobals {
  InitGlobals() {
    // Set up ICU. ICU is used internally by GURL, which is used throughout the
    // //net code. Initializing ICU is important to prevent fuzztests from
    // asserting when handling non-ASCII urls.
    CHECK(base::i18n::InitializeICU());

    // Prevent every call to get a Histogram* from leaking memory. Instead, only
    // the fist call to get each Histogram* leaks memory.
    base::StatisticsRecorder::Initialize();

    // Disable noisy logging as per "libFuzzer in Chrome" documentation:
    // testing/libfuzzer/getting_started.md#Disable-noisy-error-message-logging.
    logging::SetMinLogLevel(logging::LOG_FATAL);
  }

  // A number of tests use async code which depends on there being a message
  // loop.  Setting one up here allows tests to reuse the message loop between
  // runs.
  base::MessageLoopForIO message_loop;

  base::AtExitManager at_exit_manager;
};

InitGlobals* init_globals = new InitGlobals();

}  // namespace
