// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/base_paths.h"

#include "base/files/file_path.h"

namespace base {

bool PathProviderFuchsia(int key, FilePath* result) {
  // TODO(fuchsia): There's no API to retrieve these on Fuchsia. The app name
  // itself should be dynamic (i.e. not always "chrome") but other paths are
  // correct as fixed paths like this. See https://crbug.com/726124.
  switch (key) {
    case FILE_EXE:
      *result = FilePath("/pkg/bin/chrome");
      return true;
    case FILE_MODULE:
      *result = FilePath("/pkg/lib/chrome");
      return true;
    case DIR_SOURCE_ROOT:
      // This is only used for tests, so we return the binary location for now.
      *result = FilePath("/system");
      return true;
    case DIR_CACHE:
      *result = FilePath("/data");
      return true;
  }

  return false;
}

}  // namespace base
