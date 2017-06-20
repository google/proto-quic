// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/process_handle.h"

#include <magenta/process.h>
#include <magenta/syscalls.h>

#include "base/logging.h"

namespace base {

ProcessId GetCurrentProcId() {
  return GetProcId(GetCurrentProcessHandle());
}

ProcessHandle GetCurrentProcessHandle() {
  // Note that mx_process_self() returns a real handle, and ownership is not
  // transferred to the caller (i.e. this should never be closed).
  return mx_process_self();
}

ProcessId GetProcId(ProcessHandle process) {
  mx_info_handle_basic_t basic;
  mx_status_t status = mx_object_get_info(process, MX_INFO_HANDLE_BASIC, &basic,
                                          sizeof(basic), nullptr, nullptr);
  if (status != MX_OK) {
    DLOG(ERROR) << "mx_object_get_info failed: " << status;
    return MX_KOID_INVALID;
  }
  return basic.koid;
}

}  // namespace base
