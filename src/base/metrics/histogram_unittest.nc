// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is a "No Compile Test" suite.
// http://dev.chromium.org/developers/testing/no-compile-tests

#include "base/metrics/histogram_macros.h"

namespace base {

#if defined(NCTEST_DIFFERENT_ENUM)  // [r"\|sample\| and \|boundary\| shouldn't be of different enums"]

void WontCompile() {
  enum TypeA { A };
  enum TypeB { B };
  UMA_HISTOGRAM_ENUMERATION("", A, B);
}

#endif

}  // namespace base
