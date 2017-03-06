// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/scoped_platform_handle.h"

namespace base {

bool ScopedPlatformHandle::is_valid() const {
  return handle_.is_valid();
}

void ScopedPlatformHandle::reset() {
  handle_.reset();
}

ScopedPlatformHandle::HandleType ScopedPlatformHandle::get() const {
  return handle_.get();
}

ScopedPlatformHandle::HandleType ScopedPlatformHandle::release() {
  return handle_.release();
}

}  // namespace base
