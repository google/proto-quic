// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/process_info.h"

#include "base/time/time.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

#if !defined(OS_IOS)
TEST(ProcessInfoTest, CreationTime) {
  Time creation_time = CurrentProcessInfo::CreationTime();
  ASSERT_FALSE(creation_time.is_null());
}
#endif  // !defined(OS_IOS)

}  // namespace base
