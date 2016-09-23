// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/linux_util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/memory/singleton.h"
#include "base/process/launch.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/synchronization/lock.h"
#include "build/build_config.h"

namespace {

// Not needed for OS_CHROMEOS.
#if defined(OS_LINUX)
enum LinuxDistroState {
  STATE_DID_NOT_CHECK  = 0,
  STATE_CHECK_STARTED  = 1,
  STATE_CHECK_FINISHED = 2,
};

// Helper class for GetLinuxDistro().
class LinuxDistroHelper {
 public:
  // Retrieves the Singleton.
  static LinuxDistroHelper* GetInstance() {
    return base::Singleton<LinuxDistroHelper>::get();
  }

  // The simple state machine goes from:
  // STATE_DID_NOT_CHECK -> STATE_CHECK_STARTED -> STATE_CHECK_FINISHED.
  LinuxDistroHelper() : state_(STATE_DID_NOT_CHECK) {}
  ~LinuxDistroHelper() {}

  // Retrieve the current state, if we're in STATE_DID_NOT_CHECK,
  // we automatically move to STATE_CHECK_STARTED so nobody else will
  // do the check.
  LinuxDistroState State() {
    base::AutoLock scoped_lock(lock_);
    if (STATE_DID_NOT_CHECK == state_) {
      state_ = STATE_CHECK_STARTED;
      return STATE_DID_NOT_CHECK;
    }
    return state_;
  }

  // Indicate the check finished, move to STATE_CHECK_FINISHED.
  void CheckFinished() {
    base::AutoLock scoped_lock(lock_);
    DCHECK_EQ(STATE_CHECK_STARTED, state_);
    state_ = STATE_CHECK_FINISHED;
  }

 private:
  base::Lock lock_;
  LinuxDistroState state_;
};
#endif  // if defined(OS_LINUX)

bool GetTasksForProcess(pid_t pid, std::vector<pid_t>* tids) {
  char buf[256];
  snprintf(buf, sizeof(buf), "/proc/%d/task", pid);

  DIR* task = opendir(buf);
  if (!task) {
    DLOG(WARNING) << "Cannot open " << buf;
    return false;
  }

  struct dirent* dent;
  while ((dent = readdir(task))) {
    char* endptr;
    const unsigned long int tid_ul = strtoul(dent->d_name, &endptr, 10);
    if (tid_ul == ULONG_MAX || *endptr)
      continue;
    tids->push_back(tid_ul);
  }
  closedir(task);
  return true;
}

}  // namespace

namespace base {

// Account for the terminating null character.
static const int kDistroSize = 128 + 1;

// We use this static string to hold the Linux distro info. If we
// crash, the crash handler code will send this in the crash dump.
char g_linux_distro[kDistroSize] =
#if defined(OS_CHROMEOS)
    "CrOS";
#elif defined(OS_ANDROID)
    "Android";
#else  // if defined(OS_LINUX)
    "Unknown";
#endif

std::string GetLinuxDistro() {
#if defined(OS_CHROMEOS) || defined(OS_ANDROID)
  return g_linux_distro;
#elif defined(OS_LINUX)
  LinuxDistroHelper* distro_state_singleton = LinuxDistroHelper::GetInstance();
  LinuxDistroState state = distro_state_singleton->State();
  if (STATE_CHECK_FINISHED == state)
    return g_linux_distro;
  if (STATE_CHECK_STARTED == state)
    return "Unknown"; // Don't wait for other thread to finish.
  DCHECK_EQ(state, STATE_DID_NOT_CHECK);
  // We do this check only once per process. If it fails, there's
  // little reason to believe it will work if we attempt to run
  // lsb_release again.
  std::vector<std::string> argv;
  argv.push_back("lsb_release");
  argv.push_back("-d");
  std::string output;
  GetAppOutput(CommandLine(argv), &output);
  if (output.length() > 0) {
    // lsb_release -d should return: Description:<tab>Distro Info
    const char field[] = "Description:\t";
    if (output.compare(0, strlen(field), field) == 0) {
      SetLinuxDistro(output.substr(strlen(field)));
    }
  }
  distro_state_singleton->CheckFinished();
  return g_linux_distro;
#else
  NOTIMPLEMENTED();
  return "Unknown";
#endif
}

void SetLinuxDistro(const std::string& distro) {
  std::string trimmed_distro;
  TrimWhitespaceASCII(distro, TRIM_ALL, &trimmed_distro);
  strlcpy(g_linux_distro, trimmed_distro.c_str(), kDistroSize);
}

pid_t FindThreadIDWithSyscall(pid_t pid, const std::string& expected_data,
                              bool* syscall_supported) {
  if (syscall_supported != NULL)
    *syscall_supported = false;

  std::vector<pid_t> tids;
  if (!GetTasksForProcess(pid, &tids))
    return -1;

  std::unique_ptr<char[]> syscall_data(new char[expected_data.length()]);
  for (pid_t tid : tids) {
    char buf[256];
    snprintf(buf, sizeof(buf), "/proc/%d/task/%d/syscall", pid, tid);
    int fd = open(buf, O_RDONLY);
    if (fd < 0)
      continue;
    if (syscall_supported != NULL)
      *syscall_supported = true;
    bool read_ret = ReadFromFD(fd, syscall_data.get(), expected_data.length());
    close(fd);
    if (!read_ret)
      continue;

    if (0 == strncmp(expected_data.c_str(), syscall_data.get(),
                     expected_data.length())) {
      return tid;
    }
  }
  return -1;
}

pid_t FindThreadID(pid_t pid, pid_t ns_tid, bool* ns_pid_supported) {
  if (ns_pid_supported)
    *ns_pid_supported = false;

  std::vector<pid_t> tids;
  if (!GetTasksForProcess(pid, &tids))
    return -1;

  for (pid_t tid : tids) {
    char buf[256];
    snprintf(buf, sizeof(buf), "/proc/%d/task/%d/status", pid, tid);
    std::string status;
    if (!ReadFileToString(FilePath(buf), &status))
      return -1;
    StringPairs pairs;
    SplitStringIntoKeyValuePairs(status, ':', '\n', &pairs);
    for (const auto& pair : pairs) {
      const std::string& key = pair.first;
      const std::string& value_str = pair.second;
      if (key == "NSpid") {
        if (ns_pid_supported)
          *ns_pid_supported = true;
        std::vector<StringPiece> split_value_str = SplitStringPiece(
            value_str, "\t", TRIM_WHITESPACE, SPLIT_WANT_NONEMPTY);
        DCHECK_NE(split_value_str.size(), 0u);
        int value;
        // The last value in the list is the PID in the namespace.
        if (StringToInt(split_value_str.back(), &value) && value == ns_tid) {
          // The first value in the list is the real PID.
          if (StringToInt(split_value_str.front(), &value))
            return value;
        }
      }
    }
  }
  return -1;
}

}  // namespace base
