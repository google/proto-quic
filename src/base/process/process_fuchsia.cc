// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/process.h"

#include <magenta/process.h>
#include <magenta/syscalls.h>

#include "base/debug/activity_tracker.h"

namespace base {

Process::Process(ProcessHandle handle)
    : process_(handle), is_current_process_(false) {
  CHECK_NE(handle, mx_process_self());
}

Process::~Process() {
  Close();
}

Process::Process(Process&& other)
    : process_(other.process_), is_current_process_(other.is_current_process_) {
  other.process_ = kNullProcessHandle;
}

Process& Process::operator=(Process&& other) {
  process_ = other.process_;
  other.process_ = kNullProcessHandle;
  is_current_process_ = other.is_current_process_;
  return *this;
}

// static
Process Process::Current() {
  Process process;
  process.is_current_process_ = true;
  return process;
}

// static
Process Process::Open(ProcessId pid) {
  if (pid == GetCurrentProcId())
    return Current();

  // While a process with object id |pid| might exist, the job returned by
  // mx_job_default() might not contain it, so this call can fail.
  mx_handle_t handle;
  mx_status_t status =
      mx_object_get_child(mx_job_default(), pid, MX_RIGHT_SAME_RIGHTS, &handle);
  if (status != MX_OK) {
    DLOG(ERROR) << "mx_object_get_child failed: " << status;
    return Process();
  }
  return Process(handle);
}

// static
Process Process::OpenWithExtraPrivileges(ProcessId pid) {
  // No privileges to set.
  return Open(pid);
}

// static
Process Process::DeprecatedGetProcessFromHandle(ProcessHandle handle) {
  DCHECK_NE(handle, GetCurrentProcessHandle());
  mx_handle_t out;
  if (mx_handle_duplicate(handle, MX_RIGHT_SAME_RIGHTS, &out) != MX_OK) {
    DLOG(ERROR) << "mx_handle_duplicate failed: " << handle;
    return Process();
  }

  return Process(out);
}

// static
bool Process::CanBackgroundProcesses() {
  return false;
}

// static
void Process::TerminateCurrentProcessImmediately(int exit_code) {
  _exit(exit_code);
}

bool Process::IsValid() const {
  return process_ != kNullProcessHandle || is_current();
}

ProcessHandle Process::Handle() const {
  return is_current_process_ ? mx_process_self() : process_;
}

Process Process::Duplicate() const {
  if (is_current())
    return Current();

  if (!IsValid())
    return Process();

  mx_handle_t out;
  if (mx_handle_duplicate(process_, MX_RIGHT_SAME_RIGHTS, &out) != MX_OK) {
    DLOG(ERROR) << "mx_handle_duplicate failed: " << process_;
    return Process();
  }

  return Process(out);
}

ProcessId Process::Pid() const {
  DCHECK(IsValid());
  return GetProcId(process_);
}

bool Process::is_current() const {
  return is_current_process_;
}

void Process::Close() {
  is_current_process_ = false;
  if (IsValid()) {
    mx_status_t status = mx_handle_close(process_);
    DCHECK_EQ(status, MX_OK);
    process_ = kNullProcessHandle;
  }
}

bool Process::Terminate(int exit_code, bool wait) const {
  // exit_code isn't supportable.
  mx_status_t status = mx_task_kill(process_);
  if (status == MX_OK && wait) {
    mx_signals_t signals;
    status = mx_object_wait_one(process_, MX_TASK_TERMINATED,
                                mx_deadline_after(MX_SEC(60)), &signals);
    if (status != MX_OK) {
      DLOG(ERROR) << "Error waiting for process exit: " << status;
    } else {
      DCHECK(signals & MX_TASK_TERMINATED);
    }
  } else if (status != MX_OK) {
    DLOG(ERROR) << "Unable to terminate process: " << status;
  }

  return status >= 0;
}

bool Process::WaitForExit(int* exit_code) const {
  return WaitForExitWithTimeout(TimeDelta::Max(), exit_code);
}

bool Process::WaitForExitWithTimeout(TimeDelta timeout, int* exit_code) const {
  // Record the event that this thread is blocking upon (for hang diagnosis).
  base::debug::ScopedProcessWaitActivity process_activity(this);

  mx_time_t mxtimeout_nanos =
      timeout == TimeDelta::Max() ? MX_TIME_INFINITE : timeout.InNanoseconds();
  mx_signals_t signals_observed;
  mx_status_t status = mx_object_wait_one(process_, MX_TASK_TERMINATED,
                                          mxtimeout_nanos, &signals_observed);
  *exit_code = -1;
  if (status != MX_OK && status != MX_ERR_TIMED_OUT)
    return false;
  if (status == MX_ERR_TIMED_OUT && !signals_observed)
    return false;

  mx_info_process_t proc_info;
  status = mx_object_get_info(process_, MX_INFO_PROCESS, &proc_info,
                              sizeof(proc_info), nullptr, nullptr);
  if (status != MX_OK)
    return status;

  *exit_code = proc_info.return_code;
  return true;
}

bool Process::IsProcessBackgrounded() const {
  // See SetProcessBackgrounded().
  DCHECK(IsValid());
  return false;
}

bool Process::SetProcessBackgrounded(bool value) {
  // No process priorities on Fuchsia. TODO(fuchsia): See MG-783, and update
  // this later if priorities are implemented.
  return false;
}

int Process::GetPriority() const {
  DCHECK(IsValid());
  // No process priorities on Fuchsia.
  return 0;
}

}  // namespace base
