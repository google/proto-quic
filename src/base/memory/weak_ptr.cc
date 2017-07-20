// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/weak_ptr.h"

#include "base/debug/leak_annotations.h"

namespace base {
namespace internal {

constexpr uintptr_t kTrueMask = ~static_cast<uintptr_t>(0);

WeakReference::Flag::Flag() : is_valid_(kTrueMask) {
  // Flags only become bound when checked for validity, or invalidated,
  // so that we can check that later validity/invalidation operations on
  // the same Flag take place on the same sequenced thread.
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

WeakReference::Flag::Flag(WeakReference::Flag::NullFlagTag) : is_valid_(false) {
  // There is no need for DETACH_FROM_SEQUENCE(sequence_checker_) because the
  // null flag doesn't participate in the sequence checks. See DCHECK in
  // Invalidate() and IsValid().

  // Keep the object alive perpetually, even when there are no references to it.
  AddRef();
}

WeakReference::Flag* WeakReference::Flag::NullFlag() {
  ANNOTATE_SCOPED_MEMORY_LEAK;
  static Flag* g_null_flag = new Flag(kNullFlagTag);
  return g_null_flag;
}

void WeakReference::Flag::Invalidate() {
#if DCHECK_IS_ON()
  if (this == NullFlag()) {
    // The Null Flag does not participate in the sequence checks below.
    // Since its state never changes, it can be accessed from any thread.
    DCHECK(!is_valid_);
    return;
  }
  // The flag being invalidated with a single ref implies that there are no
  // weak pointers in existence. Allow deletion on other thread in this
  // case.
  DCHECK(sequence_checker_.CalledOnValidSequence() || HasOneRef())
      << "WeakPtrs must be invalidated on the same sequenced thread.";
#endif
  is_valid_ = 0;
}

WeakReference::Flag::~Flag() {}

WeakReference::WeakReference() : flag_(Flag::NullFlag()) {}

WeakReference::~WeakReference() {}

WeakReference::WeakReference(const Flag* flag) : flag_(flag) {}

WeakReference::WeakReference(WeakReference&& other)
    : flag_(std::move(other.flag_)) {
  other.flag_ = Flag::NullFlag();
}

WeakReference::WeakReference(const WeakReference& other) = default;

WeakReferenceOwner::WeakReferenceOwner()
    : flag_(WeakReference::Flag::NullFlag()) {}

WeakReferenceOwner::~WeakReferenceOwner() {
  Invalidate();
}

WeakReference WeakReferenceOwner::GetRef() const {
  // If we hold the last reference to the Flag then create a new one.
  if (!HasRefs())
    flag_ = new WeakReference::Flag();

  return WeakReference(flag_.get());
}

void WeakReferenceOwner::Invalidate() {
  if (flag_ != WeakReference::Flag::NullFlag()) {
    flag_->Invalidate();
    flag_ = WeakReference::Flag::NullFlag();
  }
}

WeakPtrBase::WeakPtrBase() : ptr_(0) {}

WeakPtrBase::~WeakPtrBase() {}

WeakPtrBase::WeakPtrBase(const WeakReference& ref, uintptr_t ptr)
    : ref_(ref), ptr_(ptr) {}

WeakPtrFactoryBase::WeakPtrFactoryBase(uintptr_t ptr) : ptr_(ptr) {}

WeakPtrFactoryBase::~WeakPtrFactoryBase() {
  ptr_ = 0;
}

}  // namespace internal
}  // namespace base
