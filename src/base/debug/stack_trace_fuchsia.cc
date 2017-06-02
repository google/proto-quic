// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/stack_trace.h"

#include <magenta/process.h>
#include <magenta/syscalls.h>
#include <magenta/syscalls/port.h>
#include <magenta/types.h>
#include <threads.h>
#include <unwind.h>

#include <algorithm>
#include <iostream>

#include "base/logging.h"

namespace base {
namespace debug {

namespace {

struct BacktraceData {
  void** trace_array;
  size_t* count;
  size_t max;
};

_Unwind_Reason_Code UnwindStore(struct _Unwind_Context* context,
                                void* user_data) {
  BacktraceData* data = reinterpret_cast<BacktraceData*>(user_data);
  uintptr_t pc = _Unwind_GetIP(context);
  data->trace_array[*data->count] = reinterpret_cast<void*>(pc);
  data->count += 1;
  if (*data->count == data->max)
    return _URC_END_OF_STACK;
  return _URC_NO_REASON;
}

constexpr uint64_t kExceptionKey = 0x424144u;  // "BAD".
bool g_in_process_exception_handler_enabled;

int SelfDumpFunc(void* arg) {
  mx_handle_t exception_port =
      static_cast<mx_handle_t>(reinterpret_cast<uintptr_t>(arg));

  mx_exception_packet_t packet;
  mx_status_t status =
      mx_port_wait(exception_port, MX_TIME_INFINITE, &packet, sizeof(packet));
  if (status < 0) {
    DLOG(ERROR) << "mx_port_wait failed: " << status;
    return 1;
  }
  if (packet.hdr.key != kExceptionKey) {
    DLOG(ERROR) << "unexpected crash key";
    return 1;
  }

  LOG(ERROR) << "Process crashed.";

  // TODO(fuchsia): Log a stack. See https://crbug.com/706592.

  _exit(1);
}

bool SetInProcessExceptionHandler() {
  if (g_in_process_exception_handler_enabled)
    return true;

  mx_status_t status;
  mx_handle_t self_dump_port;
  status = mx_port_create(0u, &self_dump_port);
  if (status < 0) {
    DLOG(ERROR) << "mx_port_create failed: " << status;
    return false;
  }

  // A thread to wait for and process internal exceptions.
  thrd_t self_dump_thread;
  void* self_dump_arg =
      reinterpret_cast<void*>(static_cast<uintptr_t>(self_dump_port));
  int ret = thrd_create(&self_dump_thread, SelfDumpFunc, self_dump_arg);
  if (ret != thrd_success) {
    DLOG(ERROR) << "thrd_create failed: " << ret;
    return false;
  }

  status = mx_task_bind_exception_port(mx_process_self(), self_dump_port,
                                       kExceptionKey, 0);

  if (status < 0) {
    DLOG(ERROR) << "mx_task_bind_exception_port failed: " << status;
    return false;
  }

  g_in_process_exception_handler_enabled = true;
  return true;
}

}  // namespace

// static
bool EnableInProcessStackDumping() {
  return SetInProcessExceptionHandler();
}

StackTrace::StackTrace(size_t count) : count_(0) {
  BacktraceData data = {&trace_[0], &count_,
                        std::min(count, static_cast<size_t>(kMaxTraces))};
  _Unwind_Backtrace(&UnwindStore, &data);
}

void StackTrace::Print() const {
  OutputToStream(&std::cerr);
}

void StackTrace::OutputToStream(std::ostream* os) const {
  // TODO(fuchsia): Consider doing symbol resolution here. See
  // https://crbug.com/706592.
  for (size_t i = 0; (i < count_) && os->good(); ++i) {
    (*os) << "\t" << trace_[i] << "\n";
  }
}

}  // namespace debug
}  // namespace base
