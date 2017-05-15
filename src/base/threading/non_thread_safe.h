// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_THREADING_NON_THREAD_SAFE_H_
#define BASE_THREADING_NON_THREAD_SAFE_H_

// Classes deriving from NonThreadSafe may need to suppress MSVC warning 4275:
// non dll-interface class 'Bar' used as base for dll-interface class 'Foo'.
// There is a specific macro to do it: NON_EXPORTED_BASE(), defined in
// compiler_specific.h
#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/threading/non_thread_safe_impl.h"

namespace base {

// Do nothing implementation of NonThreadSafe, for release mode.
//
// Note: You should almost always use the NonThreadSafe class to get
// the right version of the class for your build configuration.
class NonThreadSafeDoNothing {
 public:
  bool CalledOnValidThread() const {
    return true;
  }

 protected:
  ~NonThreadSafeDoNothing() {}
  void DetachFromThread() {}
};

// DEPRECATED! Use base::SequenceChecker (for thread-safety) or
// base::ThreadChecker (for thread-affinity) -- see their documentation for
// details. Use a checker as a protected member instead of inheriting from
// NonThreadSafe if you need subclasses to have access.
#if DCHECK_IS_ON()
typedef NonThreadSafeImpl NonThreadSafe;
#else
typedef NonThreadSafeDoNothing NonThreadSafe;
#endif  // DCHECK_IS_ON()

}  // namespace base

#endif  // BASE_THREADING_NON_THREAD_SAFE_H_
