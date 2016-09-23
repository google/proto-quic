// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/simple/simple_index_file.h"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>

#include "base/logging.h"

namespace disk_cache {
namespace {

struct DirCloser {
  void operator()(DIR* dir) { closedir(dir); }
};

typedef std::unique_ptr<DIR, DirCloser> ScopedDir;

}  // namespace

// static
bool SimpleIndexFile::TraverseCacheDirectory(
    const base::FilePath& cache_path,
    const EntryFileCallback& entry_file_callback) {
  const ScopedDir dir(opendir(cache_path.value().c_str()));
  if (!dir) {
    PLOG(ERROR) << "opendir " << cache_path.value();
    return false;
  }
  dirent entry, *result;
  while (readdir_r(dir.get(), &entry, &result) == 0) {
    if (!result)
      return true;  // The traversal completed successfully.
    const std::string file_name(result->d_name);
    if (file_name == "." || file_name == "..")
      continue;
    const base::FilePath file_path = cache_path.Append(
        base::FilePath(file_name));
    entry_file_callback.Run(file_path);
  }
  PLOG(ERROR) << "readdir_r " << cache_path.value();
  return false;
}

}  // namespace disk_cache
