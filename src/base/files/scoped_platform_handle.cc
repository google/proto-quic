// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/scoped_platform_handle.h"

namespace base {

ScopedPlatformHandle::ScopedPlatformHandle() : ScopedPlatformHandle(nullptr) {}

ScopedPlatformHandle::ScopedPlatformHandle(std::nullptr_t) {}

ScopedPlatformHandle::ScopedPlatformHandle(ScopedPlatformHandle&& other) =
    default;

ScopedPlatformHandle::ScopedPlatformHandle(HandleType handle)
    : handle_(handle) {}

ScopedPlatformHandle::ScopedPlatformHandle(ScopedHandleType handle)
    : handle_(std::move(handle)) {}

ScopedPlatformHandle::~ScopedPlatformHandle() {}

ScopedPlatformHandle& ScopedPlatformHandle::operator=(
    ScopedPlatformHandle&& other) = default;

ScopedPlatformHandle::ScopedHandleType ScopedPlatformHandle::Take() {
  return ScopedHandleType(release());
}

}  // namespace base
