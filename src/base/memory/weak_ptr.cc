// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/weak_ptr.h"

#include "base/debug/leak_annotations.h"

namespace base {
namespace internal {

static constexpr uintptr_t kTrueMask = ~static_cast<uintptr_t>(0);

WeakReference::Flag::Flag() : is_valid_(kTrueMask) {
#if DCHECK_IS_ON()
  // Flags only become bound when checked for validity, or invalidated,
  // so that we can check that later validity/invalidation operations on
  // the same Flag take place on the same sequenced thread.
  sequence_checker_.DetachFromSequence();
#endif
}

WeakReference::Flag::Flag(WeakReference::Flag::NullFlagTag) : is_valid_(false) {
  // There is no need for sequence_checker_.DetachFromSequence() because the
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

WeakReference::Flag::~Flag() {}

WeakReference::WeakReference() : flag_(Flag::NullFlag()) {}

WeakReference::~WeakReference() {
}

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
  flag_->Invalidate();
  flag_ = WeakReference::Flag::NullFlag();
}

WeakPtrBase::WeakPtrBase() {
}

WeakPtrBase::~WeakPtrBase() {
}

WeakPtrBase::WeakPtrBase(const WeakReference& ref) : ref_(ref) {
}

WeakPtrFactoryBase::WeakPtrFactoryBase(uintptr_t ptr) : ptr_(ptr) {}

WeakPtrFactoryBase::~WeakPtrFactoryBase() {
  ptr_ = 0;
}

}  // namespace internal
}  // namespace base
