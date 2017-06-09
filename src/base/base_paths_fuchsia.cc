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
    case FILE_MODULE:
      // TODO(fuchsia): This is incorrect per
      // https://fuchsia.googlesource.com/docs/+/master/namespaces.md, and
      // should be /pkg/{bin,lib}/something. However, binaries are currently run
      // by packing them into the system bootfs rather than running a "real"
      // installer (which doesn't currently exist). Additionally, to the
      // installer not existing, mmap() currently only works on bootfs file
      // systems (like /system) but won't for files installed dynamically in
      // other locations on other types of file systems. So, for now, we use
      // /system/ as the location for everything.
      *result = FilePath("/system/chrome");
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
