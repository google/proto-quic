// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/supports_user_data.h"

#include "base/memory/ptr_util.h"

namespace base {

SupportsUserData::SupportsUserData() {
  // Harmless to construct on a different execution sequence to subsequent
  // usage.
  sequence_checker_.DetachFromSequence();
}

SupportsUserData::Data* SupportsUserData::GetUserData(const void* key) const {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  DataMap::const_iterator found = user_data_.find(key);
  if (found != user_data_.end())
    return found->second.get();
  return NULL;
}

void SupportsUserData::SetUserData(const void* key, Data* data) {
  SetUserData(key, WrapUnique(data));
}

void SupportsUserData::SetUserData(const void* key,
                                   std::unique_ptr<Data> data) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  user_data_[key] = std::move(data);
}

void SupportsUserData::RemoveUserData(const void* key) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  user_data_.erase(key);
}

void SupportsUserData::DetachFromSequence() {
  sequence_checker_.DetachFromSequence();
}

SupportsUserData::~SupportsUserData() {
  DCHECK(sequence_checker_.CalledOnValidSequence() || user_data_.empty());
  DataMap local_user_data;
  user_data_.swap(local_user_data);
  // Now this->user_data_ is empty, and any destructors called transitively from
  // the destruction of |local_user_data| will see it that way instead of
  // examining a being-destroyed object.
}

}  // namespace base
