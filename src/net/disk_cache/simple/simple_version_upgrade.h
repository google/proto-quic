// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DISK_CACHE_SIMPLE_SIMPLE_VERSION_UPGRADE_H_
#define NET_DISK_CACHE_SIMPLE_SIMPLE_VERSION_UPGRADE_H_

// Defines functionality to upgrade the file structure of the Simple Cache
// Backend on disk. Assumes no backend operations are running simultaneously.
// Hence must be run at cache initialization step.

#include <stdint.h>

#include "net/base/net_export.h"

namespace base {
class FilePath;
}

namespace disk_cache {

// Performs all necessary disk IO to upgrade the cache structure if it is
// needed.
//
// Returns true iff no errors were found during consistency checks and all
// necessary transitions succeeded. If this function fails, there is nothing
// left to do other than dropping the whole cache directory.
NET_EXPORT_PRIVATE bool UpgradeSimpleCacheOnDisk(const base::FilePath& path);

// The format for the fake index has mistakenly acquired two extra fields that
// do not contain any useful data. Since they were equal to zero, they are now
// mandatated to be zero.
struct NET_EXPORT_PRIVATE FakeIndexData {
  FakeIndexData();

  // Must be equal to simplecache_v4::kSimpleInitialMagicNumber.
  uint64_t initial_magic_number;

  // Must be equal kSimpleVersion when the cache backend is instantiated.
  uint32_t version;

  uint32_t unused_must_be_zero1;
  uint32_t unused_must_be_zero2;
};

// Exposed for testing.
NET_EXPORT_PRIVATE bool UpgradeIndexV5V6(const base::FilePath& cache_directory);

}  // namespace disk_cache

#endif  // NET_DISK_CACHE_SIMPLE_SIMPLE_VERSION_UPGRADE_H_
