// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/ref_counted.h"

#include "base/threading/thread_collision_warner.h"

namespace base {
namespace {

#if DCHECK_IS_ON()
AtomicRefCount g_cross_thread_ref_count_access_allow_count = 0;
#endif

}  // namespace

namespace subtle {

bool RefCountedThreadSafeBase::HasOneRef() const {
  return AtomicRefCountIsOne(&ref_count_);
}

RefCountedThreadSafeBase::~RefCountedThreadSafeBase() {
#if DCHECK_IS_ON()
  DCHECK(in_dtor_) << "RefCountedThreadSafe object deleted without "
                      "calling Release()";
#endif
}

void RefCountedThreadSafeBase::AddRef() const {
#if DCHECK_IS_ON()
  DCHECK(!in_dtor_);
  DCHECK(!needs_adopt_ref_)
      << "This RefCounted object is created with non-zero reference count."
      << " The first reference to such a object has to be made by AdoptRef or"
      << " MakeRefCounted.";
#endif
  AtomicRefCountInc(&ref_count_);
}

bool RefCountedThreadSafeBase::Release() const {
#if DCHECK_IS_ON()
  DCHECK(!in_dtor_);
  DCHECK(!AtomicRefCountIsZero(&ref_count_));
#endif
  if (!AtomicRefCountDec(&ref_count_)) {
#if DCHECK_IS_ON()
    in_dtor_ = true;
#endif
    return true;
  }
  return false;
}

#if DCHECK_IS_ON()
bool RefCountedBase::CalledOnValidSequence() const {
  return sequence_checker_.CalledOnValidSequence() ||
         !AtomicRefCountIsZero(&g_cross_thread_ref_count_access_allow_count);
}
#endif

}  // namespace subtle

#if DCHECK_IS_ON()
ScopedAllowCrossThreadRefCountAccess::ScopedAllowCrossThreadRefCountAccess() {
  AtomicRefCountInc(&g_cross_thread_ref_count_access_allow_count);
}

ScopedAllowCrossThreadRefCountAccess::~ScopedAllowCrossThreadRefCountAccess() {
  AtomicRefCountDec(&g_cross_thread_ref_count_access_allow_count);
}
#endif

}  // namespace base
