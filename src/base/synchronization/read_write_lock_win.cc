// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/synchronization/read_write_lock.h"

namespace base {
namespace subtle {

ReadWriteLock::ReadWriteLock() : native_handle_(SRWLOCK_INIT) {}

ReadWriteLock::~ReadWriteLock() = default;

void ReadWriteLock::ReadAcquire() {
  ::AcquireSRWLockShared(&native_handle_);
}

void ReadWriteLock::ReadRelease() {
  ::ReleaseSRWLockShared(&native_handle_);
}

void ReadWriteLock::WriteAcquire() {
  ::AcquireSRWLockExclusive(&native_handle_);
}

void ReadWriteLock::WriteRelease() {
  ::ReleaseSRWLockExclusive(&native_handle_);
}

}  // namespace subtle
}  // namespace base
