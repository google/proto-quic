// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/cache_util.h"

#include <windows.h>

#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/win/scoped_handle.h"

namespace disk_cache {

bool MoveCache(const base::FilePath& from_path, const base::FilePath& to_path) {
  // I don't want to use the shell version of move because if something goes
  // wrong, that version will attempt to move file by file and fail at the end.
  if (!MoveFileEx(from_path.value().c_str(), to_path.value().c_str(), 0)) {
    LOG(ERROR) << "Unable to move the cache: " << GetLastError();
    return false;
  }
  return true;
}

bool DeleteCacheFile(const base::FilePath& name) {
  // We do a simple delete, without ever falling back to SHFileOperation, as the
  // version from base does.
  if (!DeleteFile(name.value().c_str())) {
    // There is an error, but we share delete access so let's see if there is a
    // file to open. Note that this code assumes that we have a handle to the
    // file at all times (even now), so nobody can have a handle that prevents
    // us from opening the file again (unless it was deleted).
    DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    DWORD access = SYNCHRONIZE;
    base::win::ScopedHandle file(CreateFile(
        name.value().c_str(), access, sharing, NULL, OPEN_EXISTING, 0, NULL));
    if (file.IsValid())
      return false;

    // Most likely there is no file to open... and that's what we wanted.
  }
  return true;
}

}  // namespace disk_cache
