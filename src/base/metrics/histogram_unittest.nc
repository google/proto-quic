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

#elif defined(NCTEST_NEGATIVE_ENUM_MAX)  // [r'static_assert failed "\|boundary\| is out of range of HistogramBase::Sample"']

void WontCompile() {
  // Buckets for enumeration start from 0, so a boundary < 0 is illegal.
  enum class TypeA { A = -1 };
  UMA_HISTOGRAM_ENUMERATION("", TypeA::A, TypeA::A);
}

#elif defined(NCTEST_ENUM_MAX_OUT_OF_RANGE)  // [r'static_assert failed "\|boundary\| is out of range of HistogramBase::Sample"']

void WontCompile() {
  // HistogramBase::Sample is an int and can't hold larger values.
  enum class TypeA : uint32_t { A = 0xffffffff };
  UMA_HISTOGRAM_ENUMERATION("", TypeA::A, TypeA::A);
}

#endif

}  // namespace base
