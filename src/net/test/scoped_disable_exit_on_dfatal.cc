// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/scoped_disable_exit_on_dfatal.h"

#include "base/logging.h"

namespace net {
namespace test {

// static
ScopedDisableExitOnDFatal* ScopedDisableExitOnDFatal::g_instance_ = NULL;

ScopedDisableExitOnDFatal::ScopedDisableExitOnDFatal() {
  CHECK(!g_instance_);
  g_instance_ = this;
  logging::SetLogAssertHandler(LogAssertHandler);
}

ScopedDisableExitOnDFatal::~ScopedDisableExitOnDFatal() {
  CHECK_EQ(g_instance_, this);
  logging::SetLogAssertHandler(NULL);
  g_instance_ = NULL;
}

// static
void ScopedDisableExitOnDFatal::LogAssertHandler(const std::string& str) {
  // Simply swallow the assert.
}

}  // namespace test
}  // namespace net
