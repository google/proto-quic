// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/memory_mapped_file.h"

#include <utility>

#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/sys_info.h"
#include "build/build_config.h"

namespace base {

const MemoryMappedFile::Region MemoryMappedFile::Region::kWholeFile = {0, 0};

bool MemoryMappedFile::Region::operator==(
    const MemoryMappedFile::Region& other) const {
  return other.offset == offset && other.size == size;
}

bool MemoryMappedFile::Region::operator!=(
    const MemoryMappedFile::Region& other) const {
  return other.offset != offset || other.size != size;
}

MemoryMappedFile::~MemoryMappedFile() {
  CloseHandles();
}

#if !defined(OS_NACL)
bool MemoryMappedFile::Initialize(const FilePath& file_name, Access access) {
  if (IsValid())
    return false;

  uint32_t flags = 0;
  switch (access) {
    case READ_ONLY:
      flags = File::FLAG_OPEN | File::FLAG_READ;
      break;
    case READ_WRITE:
      flags = File::FLAG_OPEN | File::FLAG_READ | File::FLAG_WRITE;
      break;
    case READ_WRITE_EXTEND:
      // Can't open with "extend" because no maximum size is known.
      NOTREACHED();
  }
  file_.Initialize(file_name, flags);

  if (!file_.IsValid()) {
    DLOG(ERROR) << "Couldn't open " << file_name.AsUTF8Unsafe();
    return false;
  }

  if (!MapFileRegionToMemory(Region::kWholeFile, access)) {
    CloseHandles();
    return false;
  }

  return true;
}

bool MemoryMappedFile::Initialize(File file, Access access) {
  DCHECK_NE(READ_WRITE_EXTEND, access);
  return Initialize(std::move(file), Region::kWholeFile, access);
}

bool MemoryMappedFile::Initialize(File file,
                                  const Region& region,
                                  Access access) {
  switch (access) {
    case READ_WRITE_EXTEND:
      DCHECK(Region::kWholeFile != region);
      // Ensure that the extended size is within limits of File.
      if (region.size > std::numeric_limits<int64_t>::max() - region.offset) {
        DLOG(ERROR) << "Region bounds exceed maximum for base::File.";
        return false;
      }
      // Fall through.
    case READ_ONLY:
    case READ_WRITE:
      // Ensure that the region values are valid.
      if (region.offset < 0 || region.size < 0) {
        DLOG(ERROR) << "Region bounds are not valid.";
        return false;
      }
      break;
  }

  if (IsValid())
    return false;

  if (region != Region::kWholeFile) {
    DCHECK_GE(region.offset, 0);
    DCHECK_GT(region.size, 0);
  }

  file_ = std::move(file);

  if (!MapFileRegionToMemory(region, access)) {
    CloseHandles();
    return false;
  }

  return true;
}

bool MemoryMappedFile::IsValid() const {
  return data_ != NULL;
}

// static
void MemoryMappedFile::CalculateVMAlignedBoundaries(int64_t start,
                                                    int64_t size,
                                                    int64_t* aligned_start,
                                                    int64_t* aligned_size,
                                                    int32_t* offset) {
  // Sadly, on Windows, the mmap alignment is not just equal to the page size.
  const int64_t mask =
      static_cast<int64_t>(SysInfo::VMAllocationGranularity()) - 1;
  DCHECK_LT(mask, std::numeric_limits<int32_t>::max());
  *offset = start & mask;
  *aligned_start = start & ~mask;
  *aligned_size = (size + *offset + mask) & ~mask;
}
#endif

}  // namespace base
