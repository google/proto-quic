// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/shared_memory_handle.h"

#include <magenta/syscalls.h>

#include "base/logging.h"
#include "base/unguessable_token.h"

namespace base {

SharedMemoryHandle::SharedMemoryHandle() {}

SharedMemoryHandle::SharedMemoryHandle(mx_handle_t h,
                                       size_t size,
                                       const base::UnguessableToken& guid)
    : handle_(h), guid_(guid), size_(size) {}

void SharedMemoryHandle::Close() const {
  DCHECK(handle_ != MX_HANDLE_INVALID);
  mx_handle_close(handle_);
}

bool SharedMemoryHandle::IsValid() const {
  return handle_ != MX_HANDLE_INVALID;
}

SharedMemoryHandle SharedMemoryHandle::Duplicate() const {
  mx_handle_t duped_handle;
  mx_status_t status =
      mx_handle_duplicate(handle_, MX_RIGHT_SAME_RIGHTS, &duped_handle);
  if (status != MX_OK)
    return SharedMemoryHandle();

  SharedMemoryHandle handle(duped_handle, GetSize(), GetGUID());
  handle.SetOwnershipPassesToIPC(true);
  return handle;
}

mx_handle_t SharedMemoryHandle::GetHandle() const {
  return handle_;
}

void SharedMemoryHandle::SetOwnershipPassesToIPC(bool ownership_passes) {
  ownership_passes_to_ipc_ = ownership_passes;
}

bool SharedMemoryHandle::OwnershipPassesToIPC() const {
  return ownership_passes_to_ipc_;
}

}  // namespace base
