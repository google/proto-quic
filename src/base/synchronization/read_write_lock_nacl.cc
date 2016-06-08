// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/synchronization/read_write_lock.h"

#include "base/logging.h"

namespace base {
namespace subtle {

ReadWriteLock::ReadWriteLock() {}

ReadWriteLock::~ReadWriteLock() {
  DCHECK_EQ(0u, readers_);
  int result = pthread_mutex_destroy(&writer_lock_);
  DCHECK_EQ(result, 0) << ". " << strerror(result);
}

void ReadWriteLock::ReadAcquire() {
  AutoLock hold(native_handle_);
  readers_++;
  if (readers_ == 1) {
    int result = pthread_mutex_lock(&writer_lock_);
    DCHECK_EQ(result, 0) << ". " << strerror(result);
  }
}

void ReadWriteLock::ReadRelease() {
  AutoLock hold(native_handle_);
  readers_--;
  if (readers_ == 0) {
    int result = pthread_mutex_unlock(&writer_lock_);
    DCHECK_EQ(result, 0) << ". " << strerror(result);
  }
}

void ReadWriteLock::WriteAcquire() {
  int result = pthread_mutex_lock(&writer_lock_);
  DCHECK_EQ(result, 0) << ". " << strerror(result);
}

void ReadWriteLock::WriteRelease() {
  int result = pthread_mutex_unlock(&writer_lock_);
  DCHECK_EQ(result, 0) << ". " << strerror(result);
}

}  // namespace subtle
}  // namespace base
