// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_NUMERICS_RANGES_H_
#define BASE_NUMERICS_RANGES_H_

#include <algorithm>

namespace base {

template <typename T>
T ClampToRange(T value, T min, T max) {
  return std::min(std::max(value, min), max);
}

}  // namespace base

#endif  // BASE_NUMERICS_RANGES_H_
