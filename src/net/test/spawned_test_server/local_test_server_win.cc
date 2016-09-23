// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/spawned_test_server/local_test_server.h"

#include <windows.h>

#include "base/base_paths.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/files/file_path.h"
#include "base/message_loop/message_loop.h"
#include "base/process/launch.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/test_timeouts.h"
#include "base/threading/thread.h"
#include "base/win/scoped_handle.h"
#include "net/test/python_utils.h"

namespace {

// Writes |size| bytes to |handle| and sets |*unblocked| to true.
// Used as a crude timeout mechanism by ReadData().
void UnblockPipe(HANDLE handle, DWORD size, bool* unblocked) {
  std::string unblock_data(size, '\0');
  // Unblock the ReadFile in LocalTestServer::WaitToStart by writing to the
  // pipe. Make sure the call succeeded, otherwise we are very likely to hang.
  DWORD bytes_written = 0;
  LOG(WARNING) << "Timeout reached; unblocking pipe by writing "
               << size << " bytes";
  CHECK(WriteFile(handle, unblock_data.data(), size, &bytes_written,
                  NULL));
  CHECK_EQ(size, bytes_written);
  *unblocked = true;
}

// Given a file handle, reads into |buffer| until |bytes_max| bytes
// has been read or an error has been encountered.  Returns
// true if the read was successful.
bool ReadData(HANDLE read_fd,
              HANDLE write_fd,
              DWORD bytes_max,
              uint8_t* buffer) {
  base::Thread thread("test_server_watcher");
  if (!thread.Start())
    return false;

  // Prepare a timeout in case the server fails to start.
  bool unblocked = false;
  thread.task_runner()->PostDelayedTask(
      FROM_HERE, base::Bind(UnblockPipe, write_fd, bytes_max, &unblocked),
      TestTimeouts::action_max_timeout());

  DWORD bytes_read = 0;
  while (bytes_read < bytes_max) {
    DWORD num_bytes;
    if (!ReadFile(read_fd, buffer + bytes_read, bytes_max - bytes_read,
                  &num_bytes, NULL)) {
      PLOG(ERROR) << "ReadFile failed";
      return false;
    }
    if (num_bytes <= 0) {
      LOG(ERROR) << "ReadFile returned invalid byte count: " << num_bytes;
      return false;
    }
    bytes_read += num_bytes;
  }

  thread.Stop();
  // If the timeout kicked in, abort.
  if (unblocked) {
    LOG(ERROR) << "Timeout exceeded for ReadData";
    return false;
  }

  return true;
}

}  // namespace

namespace net {

bool LocalTestServer::LaunchPython(const base::FilePath& testserver_path) {
  base::CommandLine python_command(base::CommandLine::NO_PROGRAM);
  if (!GetPythonCommand(&python_command))
    return false;

  python_command.AppendArgPath(testserver_path);
  if (!AddCommandLineArguments(&python_command))
    return false;

  HANDLE child_read = NULL;
  HANDLE child_write = NULL;
  if (!CreatePipe(&child_read, &child_write, NULL, 0)) {
    PLOG(ERROR) << "Failed to create pipe";
    return false;
  }
  child_read_fd_.Set(child_read);
  child_write_fd_.Set(child_write);

  // Have the child inherit the write half.
  if (!::DuplicateHandle(::GetCurrentProcess(), child_write,
                         ::GetCurrentProcess(), &child_write, 0, TRUE,
                         DUPLICATE_SAME_ACCESS)) {
    PLOG(ERROR) << "Failed to enable pipe inheritance";
    return false;
  }

  // Pass the handle on the command-line. Although HANDLE is a
  // pointer, truncating it on 64-bit machines is okay. See
  // http://msdn.microsoft.com/en-us/library/aa384203.aspx
  //
  // "64-bit versions of Windows use 32-bit handles for
  // interoperability. When sharing a handle between 32-bit and 64-bit
  // applications, only the lower 32 bits are significant, so it is
  // safe to truncate the handle (when passing it from 64-bit to
  // 32-bit) or sign-extend the handle (when passing it from 32-bit to
  // 64-bit)."
  python_command.AppendArg("--startup-pipe=" +
      base::IntToString(reinterpret_cast<uintptr_t>(child_write)));

  base::LaunchOptions launch_options;
  launch_options.inherit_handles = true;
  process_ = base::LaunchProcess(python_command, launch_options);
  if (!process_.IsValid()) {
    LOG(ERROR) << "Failed to launch " << python_command.GetCommandLineString();
    ::CloseHandle(child_write);
    return false;
  }

  ::CloseHandle(child_write);
  return true;
}

bool LocalTestServer::WaitToStart() {
  base::win::ScopedHandle read_fd(child_read_fd_.Take());
  base::win::ScopedHandle write_fd(child_write_fd_.Take());

  uint32_t server_data_len = 0;
  if (!ReadData(read_fd.Get(), write_fd.Get(), sizeof(server_data_len),
                reinterpret_cast<uint8_t*>(&server_data_len))) {
    LOG(ERROR) << "Could not read server_data_len";
    return false;
  }
  std::string server_data(server_data_len, '\0');
  if (!ReadData(read_fd.Get(), write_fd.Get(), server_data_len,
                reinterpret_cast<uint8_t*>(&server_data[0]))) {
    LOG(ERROR) << "Could not read server_data (" << server_data_len
               << " bytes)";
    return false;
  }

  if (!ParseServerData(server_data)) {
    LOG(ERROR) << "Could not parse server_data: " << server_data;
    return false;
  }

  return true;
}

}  // namespace net

