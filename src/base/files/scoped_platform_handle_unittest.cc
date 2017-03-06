// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/scoped_platform_handle.h"

#include "base/files/file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/macros.h"
#include "base/strings/stringprintf.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(OS_WIN)
#include <windows.h>

#include "base/win/scoped_handle.h"
#elif defined(OS_POSIX)
#include "base/files/scoped_file.h"
#endif

namespace base {
namespace {

class ScopedPlatformHandleTest : public testing::Test {
 public:
  ScopedPlatformHandleTest() { CHECK(temp_dir_.CreateUniqueTempDir()); }

 protected:
  ScopedPlatformHandle CreateValidHandle() {
    return ScopedPlatformHandle(OpenTempFile().TakePlatformFile());
  }

 private:
  base::File OpenTempFile() {
    base::File temp_file(temp_dir_.GetPath().AppendASCII(
                             base::StringPrintf("file_%d", next_file_id_)),
                         base::File::FLAG_CREATE | base::File::FLAG_WRITE);
    ++next_file_id_;
    return temp_file;
  }

  ScopedTempDir temp_dir_;
  int next_file_id_ = 1;

  DISALLOW_COPY_AND_ASSIGN(ScopedPlatformHandleTest);
};

TEST_F(ScopedPlatformHandleTest, Invalid) {
  ScopedPlatformHandle default_value;
  EXPECT_TRUE(!default_value.is_valid());

  ScopedPlatformHandle null_value(nullptr);
  EXPECT_TRUE(!null_value.is_valid());

  default_value.reset();
  null_value.reset();
  EXPECT_TRUE(!default_value.is_valid());
  EXPECT_TRUE(!null_value.is_valid());
}

TEST_F(ScopedPlatformHandleTest, BasicUsage) {
  ScopedPlatformHandle handle_a = CreateValidHandle();
  ScopedPlatformHandle handle_b = CreateValidHandle();
  EXPECT_TRUE(handle_a.is_valid());
  EXPECT_TRUE(handle_b.is_valid());

  ScopedPlatformHandle::HandleType handle_a_value = handle_a.get();
  ScopedPlatformHandle::HandleType handle_b_value = handle_b.get();
  EXPECT_TRUE(handle_a.is_valid());
  EXPECT_TRUE(handle_b.is_valid());

  ScopedPlatformHandle::ScopedHandleType scoped_handle = handle_a.Take();
  ScopedPlatformHandle::HandleType raw_handle = handle_b.release();
  EXPECT_FALSE(handle_a.is_valid());
  EXPECT_FALSE(handle_b.is_valid());

  handle_a = ScopedPlatformHandle(std::move(scoped_handle));
  handle_b = ScopedPlatformHandle(raw_handle);
  EXPECT_TRUE(handle_a.is_valid());
  EXPECT_TRUE(handle_b.is_valid());
  EXPECT_EQ(handle_a_value, handle_a.get());
  EXPECT_EQ(handle_b_value, handle_b.get());

  handle_b = std::move(handle_a);
  EXPECT_FALSE(handle_a.is_valid());
  EXPECT_TRUE(handle_b.is_valid());
  EXPECT_EQ(handle_a_value, handle_b.get());

  handle_b.reset();
  EXPECT_FALSE(handle_b.is_valid());
}

}  // namespace
}  // namespace base
