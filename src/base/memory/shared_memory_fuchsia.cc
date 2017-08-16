// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/shared_memory.h"

#include <limits>

#include <magenta/process.h>
#include <magenta/rights.h>
#include <magenta/syscalls.h>

#include "base/bits.h"
#include "base/fuchsia/scoped_mx_handle.h"
#include "base/logging.h"
#include "base/memory/shared_memory_tracker.h"
#include "base/process/process_metrics.h"

namespace base {

SharedMemory::SharedMemory() {}

SharedMemory::SharedMemory(const SharedMemoryHandle& handle, bool read_only)
    : shm_(handle), read_only_(read_only) {}

SharedMemory::~SharedMemory() {
  Unmap();
  Close();
}

// static
bool SharedMemory::IsHandleValid(const SharedMemoryHandle& handle) {
  return handle.IsValid();
}

// static
void SharedMemory::CloseHandle(const SharedMemoryHandle& handle) {
  DCHECK(handle.IsValid());
  handle.Close();
}

// static
size_t SharedMemory::GetHandleLimit() {
  // No documented limit, currently.
  return std::numeric_limits<size_t>::max();
}

bool SharedMemory::CreateAndMapAnonymous(size_t size) {
  return CreateAnonymous(size) && Map(size);
}

bool SharedMemory::Create(const SharedMemoryCreateOptions& options) {
  requested_size_ = options.size;
  mapped_size_ = bits::Align(requested_size_, GetPageSize());
  ScopedMxHandle vmo;
  mx_status_t status = mx_vmo_create(mapped_size_, 0, vmo.receive());
  if (status != MX_OK) {
    DLOG(ERROR) << "mx_vmo_create failed, status=" << status;
    return false;
  }

  if (!options.executable) {
    // If options.executable isn't set, drop that permission by replacement.
    const int kNoExecFlags = MX_DEFAULT_VMO_RIGHTS & ~MX_RIGHT_EXECUTE;
    ScopedMxHandle old_vmo(std::move(vmo));
    status = mx_handle_replace(old_vmo.get(), kNoExecFlags, vmo.receive());
    if (status != MX_OK) {
      DLOG(ERROR) << "mx_handle_replace() failed: "
                  << mx_status_get_string(status);
      return false;
    }
    ignore_result(old_vmo.release());
  }

  shm_ = SharedMemoryHandle(vmo.release(), mapped_size_,
                            UnguessableToken::Create());
  return true;
}

bool SharedMemory::MapAt(off_t offset, size_t bytes) {
  if (!shm_.IsValid())
    return false;

  if (bytes > static_cast<size_t>(std::numeric_limits<int>::max()))
    return false;

  if (memory_)
    return false;

  int flags = MX_VM_FLAG_PERM_READ;
  if (!read_only_)
    flags |= MX_VM_FLAG_PERM_WRITE;
  uintptr_t addr;
  mx_status_t status = mx_vmar_map(mx_vmar_root_self(), 0, shm_.GetHandle(),
                                   offset, bytes, flags, &addr);
  if (status != MX_OK) {
    DLOG(ERROR) << "mx_vmar_map failed, status=" << status;
    return false;
  }
  memory_ = reinterpret_cast<void*>(addr);

  mapped_size_ = bytes;
  mapped_id_ = shm_.GetGUID();
  SharedMemoryTracker::GetInstance()->IncrementMemoryUsage(*this);
  return true;
}

bool SharedMemory::Unmap() {
  if (!memory_)
    return false;

  SharedMemoryTracker::GetInstance()->DecrementMemoryUsage(*this);

  uintptr_t addr = reinterpret_cast<uintptr_t>(memory_);
  mx_status_t status = mx_vmar_unmap(mx_vmar_root_self(), addr, mapped_size_);
  if (status != MX_OK) {
    DLOG(ERROR) << "mx_vmar_unmap failed, status=" << status;
    return false;
  }

  memory_ = nullptr;
  mapped_id_ = UnguessableToken();
  return true;
}

void SharedMemory::Close() {
  if (shm_.IsValid()) {
    shm_.Close();
    shm_ = SharedMemoryHandle();
  }
}

SharedMemoryHandle SharedMemory::handle() const {
  return shm_;
}

SharedMemoryHandle SharedMemory::TakeHandle() {
  SharedMemoryHandle handle(shm_);
  handle.SetOwnershipPassesToIPC(true);
  shm_ = SharedMemoryHandle();
  memory_ = nullptr;
  mapped_size_ = 0;
  return handle;
}

SharedMemoryHandle SharedMemory::DuplicateHandle(
    const SharedMemoryHandle& handle) {
  return handle.Duplicate();
}

SharedMemoryHandle SharedMemory::GetReadOnlyHandle() {
  mx_handle_t duped_handle;
  const int kNoWriteOrExec =
      MX_DEFAULT_VMO_RIGHTS &
      ~(MX_RIGHT_WRITE | MX_RIGHT_EXECUTE | MX_RIGHT_SET_PROPERTY);
  mx_status_t status =
      mx_handle_duplicate(shm_.GetHandle(), kNoWriteOrExec, &duped_handle);
  if (status != MX_OK)
    return SharedMemoryHandle();

  SharedMemoryHandle handle(duped_handle, shm_.GetSize(), shm_.GetGUID());
  handle.SetOwnershipPassesToIPC(true);
  return handle;
}

}  // namespace base
