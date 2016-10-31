// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/memory_coordinator_proxy.h"

namespace base {

MemoryCoordinatorProxy::MemoryCoordinatorProxy() {
}

MemoryCoordinatorProxy::~MemoryCoordinatorProxy() {
}

MemoryCoordinatorProxy* MemoryCoordinatorProxy::GetInstance() {
  return Singleton<base::MemoryCoordinatorProxy>::get();
}

MemoryState MemoryCoordinatorProxy::GetCurrentMemoryState() const {
  if (!getter_callback_)
    return MemoryState::NORMAL;
  return getter_callback_.Run();
}

void MemoryCoordinatorProxy::SetCurrentMemoryStateForTesting(
    MemoryState memory_state) {
  DCHECK(setter_callback_);
  setter_callback_.Run(memory_state);
}

void MemoryCoordinatorProxy::SetGetCurrentMemoryStateCallback(
    GetCurrentMemoryStateCallback callback) {
  getter_callback_ = callback;
}

void MemoryCoordinatorProxy::SetSetCurrentMemoryStateForTestingCallback(
    SetCurrentMemoryStateCallback callback) {
  setter_callback_ = callback;
}

}  // namespace base
