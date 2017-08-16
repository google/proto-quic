// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_THREADING_SCOPED_MAY_BLOCK_H
#define BASE_THREADING_SCOPED_MAY_BLOCK_H

#include "base/base_export.h"

namespace base {

// This class should be instantiated in every scope where a blocking call is
// made.
//
// Instantiation will hint the BlockingObserver for this thread about the
// scope of the blocking operation. In particular, on TaskScheduler owned
// threads, this will allow the thread to be replaced in its pool if the
// blocking scope doesn't expire shortly.
class BASE_EXPORT ScopedMayBlock {
 public:
  ScopedMayBlock();
  ~ScopedMayBlock();
};

namespace internal {

// Interface for an observer to be informed when a thread enters or exits
// the scope of a ScopedMayBlock object.
class BASE_EXPORT BlockingObserver {
 public:
  virtual void BlockingScopeEntered() = 0;
  virtual void BlockingScopeExited() = 0;
};

void SetBlockingObserverForCurrentThread(BlockingObserver* blocking_observer);

}  // namespace internal

}  // namespace base

#endif  // BASE_THREADING_SCOPED_MAY_BLOCK_H
