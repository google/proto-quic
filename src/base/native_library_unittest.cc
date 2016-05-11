// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/file_path.h"
#include "base/native_library.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

const FilePath::CharType kDummyLibraryPath[] =
    FILE_PATH_LITERAL("dummy_library");

TEST(NativeLibraryTest, LoadFailure) {
  NativeLibraryLoadError error;
  NativeLibrary library =
      LoadNativeLibrary(FilePath(kDummyLibraryPath), &error);
  EXPECT_TRUE(library == nullptr);
  EXPECT_FALSE(error.ToString().empty());
}

// |error| is optional and can be null.
TEST(NativeLibraryTest, LoadFailureWithNullError) {
  NativeLibrary library =
      LoadNativeLibrary(FilePath(kDummyLibraryPath), nullptr);
  EXPECT_TRUE(library == nullptr);
}

}  // namespace base
