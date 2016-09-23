// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/platform_thread.h"

#include <errno.h>
#include <sched.h>
#include <stddef.h>

#include "base/files/file_util.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/platform_thread_internal_posix.h"
#include "base/threading/thread_id_name_manager.h"
#include "base/tracked_objects.h"
#include "build/build_config.h"

#if !defined(OS_NACL)
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace base {
namespace {
#if !defined(OS_NACL)
const FilePath::CharType kCpusetDirectory[] =
    FILE_PATH_LITERAL("/sys/fs/cgroup/cpuset/chrome");

FilePath ThreadPriorityToCpusetDirectory(ThreadPriority priority) {
  FilePath cpuset_filepath(kCpusetDirectory);
  switch (priority) {
    case ThreadPriority::NORMAL:
      return cpuset_filepath;
    case ThreadPriority::BACKGROUND:
      return cpuset_filepath.Append(FILE_PATH_LITERAL("non-urgent"));
    case ThreadPriority::DISPLAY:
    case ThreadPriority::REALTIME_AUDIO:
      return cpuset_filepath.Append(FILE_PATH_LITERAL("urgent"));
  }
  NOTREACHED();
  return FilePath();
}

void SetThreadCpuset(PlatformThreadId thread_id,
                     const FilePath& cpuset_directory) {
  // Silently ignore request if cpuset directory doesn't exist.
  if (!DirectoryExists(cpuset_directory))
    return;
  FilePath tasks_filepath = cpuset_directory.Append(FILE_PATH_LITERAL("tasks"));
  std::string tid = IntToString(thread_id);
  int bytes_written = WriteFile(tasks_filepath, tid.c_str(), tid.size());
  if (bytes_written != static_cast<int>(tid.size())) {
    DVLOG(1) << "Failed to add " << tid << " to " << tasks_filepath.value();
  }
}
#endif
}  // namespace

namespace internal {

namespace {
#if !defined(OS_NACL)
const struct sched_param kRealTimePrio = {8};
#endif
}  // namespace

const ThreadPriorityToNiceValuePair kThreadPriorityToNiceValueMap[4] = {
    {ThreadPriority::BACKGROUND, 10},
    {ThreadPriority::NORMAL, 0},
    {ThreadPriority::DISPLAY, -8},
    {ThreadPriority::REALTIME_AUDIO, -10},
};

bool SetCurrentThreadPriorityForPlatform(ThreadPriority priority) {
#if !defined(OS_NACL)
  FilePath cpuset_directory = ThreadPriorityToCpusetDirectory(priority);
  SetThreadCpuset(PlatformThread::CurrentId(), cpuset_directory);
  return priority == ThreadPriority::REALTIME_AUDIO &&
         pthread_setschedparam(pthread_self(), SCHED_RR, &kRealTimePrio) == 0;
#else
  return false;
#endif
}

bool GetCurrentThreadPriorityForPlatform(ThreadPriority* priority) {
#if !defined(OS_NACL)
  int maybe_sched_rr = 0;
  struct sched_param maybe_realtime_prio = {0};
  if (pthread_getschedparam(pthread_self(), &maybe_sched_rr,
                            &maybe_realtime_prio) == 0 &&
      maybe_sched_rr == SCHED_RR &&
      maybe_realtime_prio.sched_priority == kRealTimePrio.sched_priority) {
    *priority = ThreadPriority::REALTIME_AUDIO;
    return true;
  }
#endif
  return false;
}

}  // namespace internal

// static
void PlatformThread::SetName(const std::string& name) {
  ThreadIdNameManager::GetInstance()->SetName(CurrentId(), name);
  tracked_objects::ThreadData::InitializeThreadContext(name);

#if !defined(OS_NACL)
  // On linux we can get the thread names to show up in the debugger by setting
  // the process name for the LWP.  We don't want to do this for the main
  // thread because that would rename the process, causing tools like killall
  // to stop working.
  if (PlatformThread::CurrentId() == getpid())
    return;

  // http://0pointer.de/blog/projects/name-your-threads.html
  // Set the name for the LWP (which gets truncated to 15 characters).
  // Note that glibc also has a 'pthread_setname_np' api, but it may not be
  // available everywhere and it's only benefit over using prctl directly is
  // that it can set the name of threads other than the current thread.
  int err = prctl(PR_SET_NAME, name.c_str());
  // We expect EPERM failures in sandboxed processes, just ignore those.
  if (err < 0 && errno != EPERM)
    DPLOG(ERROR) << "prctl(PR_SET_NAME)";
#endif  //  !defined(OS_NACL)
}

#if !defined(OS_NACL)
// static
void PlatformThread::SetThreadPriority(PlatformThreadId thread_id,
                                       ThreadPriority priority) {
  // Changing current main threads' priority is not permitted in favor of
  // security, this interface is restricted to change only non-main thread
  // priority.
  CHECK_NE(thread_id, getpid());

  FilePath cpuset_directory = ThreadPriorityToCpusetDirectory(priority);
  SetThreadCpuset(thread_id, cpuset_directory);

  const int nice_setting = internal::ThreadPriorityToNiceValue(priority);
  if (setpriority(PRIO_PROCESS, thread_id, nice_setting)) {
    DVPLOG(1) << "Failed to set nice value of thread (" << thread_id << ") to "
              << nice_setting;
  }
}
#endif  //  !defined(OS_NACL)

void InitThreading() {}

void TerminateOnThread() {}

size_t GetDefaultThreadStackSize(const pthread_attr_t& attributes) {
#if !defined(THREAD_SANITIZER)
  return 0;
#else
  // ThreadSanitizer bloats the stack heavily. Evidence has been that the
  // default stack size isn't enough for some browser tests.
  return 2 * (1 << 23);  // 2 times 8192K (the default stack size on Linux).
#endif
}

}  // namespace base
