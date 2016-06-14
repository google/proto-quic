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
  EXPECT_FALSE(LoadNativeLibrary(FilePath(kDummyLibraryPath), &error));
  EXPECT_FALSE(error.ToString().empty());
}

// |error| is optional and can be null.
TEST(NativeLibraryTest, LoadFailureWithNullError) {
  EXPECT_FALSE(LoadNativeLibrary(FilePath(kDummyLibraryPath), nullptr));
}

TEST(NativeLibraryTest, GetNativeLibraryName) {
  const char kExpectedName[] =
#if defined(OS_IOS)
      "mylib";
#elif defined(OS_MACOSX)
      "libmylib.dylib";
#elif defined(OS_POSIX)
      "libmylib.so";
#elif defined(OS_WIN)
      "mylib.dll";
#endif
  EXPECT_EQ(kExpectedName, GetNativeLibraryName("mylib"));
}

}  // namespace base
