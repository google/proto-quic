// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_FILES_SCOPED_PLATFORM_HANDLE_H_
#define BASE_FILES_SCOPED_PLATFORM_HANDLE_H_

#include <stddef.h>
#include <stdint.h>

#include "base/base_export.h"
#include "build/build_config.h"

#if defined(OS_WIN)
#include <windows.h>

#include "base/win/scoped_handle.h"
#elif defined(OS_POSIX)
#include "base/files/scoped_file.h"
#endif

namespace base {

// A ScopedPlatformHandle encapsulates ownership of either a Windows handle or
// a POSIX file descriptor, while presenting a common interface for the sake
// of simple, consistent, and safe ownership semantics. Platform-specific usage
// details are thus relegated to code which either acquires or uses the
// underlying platform resource.
class BASE_EXPORT ScopedPlatformHandle {
 public:
#if defined(OS_WIN)
  using HandleType = HANDLE;
  using ScopedHandleType = win::ScopedHandle;
#elif defined(OS_POSIX)
  using HandleType = int;
  using ScopedHandleType = ScopedFD;
#endif

  // Constructors for an invalid ScopedPlatformHandle.
  ScopedPlatformHandle();
  ScopedPlatformHandle(std::nullptr_t);

  ScopedPlatformHandle(ScopedPlatformHandle&& other);

  // These constructors always take ownership of the given handle.
  explicit ScopedPlatformHandle(HandleType handle);
  explicit ScopedPlatformHandle(ScopedHandleType handle);

  ~ScopedPlatformHandle();

  ScopedPlatformHandle& operator=(ScopedPlatformHandle&& other);

  // Indicates whether this ScopedPlatformHandle is holding a valid handle.
  bool is_valid() const;

  // Closes the handle.
  void reset();

  // Returns the platform-specific handle value.
  HandleType get() const;

  // Returns the platform-specific handle value, releasing ownership of the
  // handle.
  HandleType release();

  // Transfers ownership of the handle to a platform-specific scoper.
  ScopedHandleType Take();

 private:
  ScopedHandleType handle_;
};

}  // namespace base

#endif  // BASE_FILES_SCOPED_PLATFORM_HANDLE_H_
