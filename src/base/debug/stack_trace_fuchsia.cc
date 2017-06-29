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
  *data->count += 1;
  if (*data->count == data->max)
    return _URC_END_OF_STACK;
  return _URC_NO_REASON;
}

}  // namespace

// static
bool EnableInProcessStackDumping() {
  // StackTrace works to capture the current stack (e.g. for diagnostics added
  // to code), but for local capture and print of backtraces, we just let the
  // system crashlogger take over. It handles printing out a nicely formatted
  // backtrace with dso information, relative offsets, etc. that we can then
  // filter with addr2line in the run script to get file/line info.
  return true;
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
