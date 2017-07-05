// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/ref_counted.h"

#include "base/threading/thread_collision_warner.h"

namespace base {
namespace {

#if DCHECK_IS_ON()
AtomicRefCount g_cross_thread_ref_count_access_allow_count(0);
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

#if !defined(ARCH_CPU_X86_FAMILY)
bool RefCountedThreadSafeBase::Release() const {
  return ReleaseImpl();
}
void RefCountedThreadSafeBase::AddRef() const {
  AddRefImpl();
}
#endif

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
