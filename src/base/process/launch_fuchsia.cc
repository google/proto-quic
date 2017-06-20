// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/launch.h"

#include <launchpad/launchpad.h>
#include <magenta/process.h>
#include <unistd.h>

#include "base/command_line.h"
#include "base/logging.h"

namespace base {

namespace {

bool GetAppOutputInternal(const std::vector<std::string>& argv,
                          bool include_stderr,
                          std::string* output,
                          int* exit_code) {
  DCHECK(exit_code);

  std::vector<const char*> argv_cstr;
  argv_cstr.reserve(argv.size() + 1);
  for (const auto& arg : argv)
    argv_cstr.push_back(arg.c_str());
  argv_cstr.push_back(nullptr);

  launchpad_t* lp;
  launchpad_create(MX_HANDLE_INVALID, argv_cstr[0], &lp);
  launchpad_load_from_file(lp, argv_cstr[0]);
  launchpad_set_args(lp, argv.size(), argv_cstr.data());
  launchpad_clone(lp, LP_CLONE_MXIO_ROOT | LP_CLONE_MXIO_CWD |
                          LP_CLONE_DEFAULT_JOB | LP_CLONE_ENVIRON);
  launchpad_clone_fd(lp, STDIN_FILENO, STDIN_FILENO);
  int pipe_fd;
  mx_status_t status = launchpad_add_pipe(lp, &pipe_fd, STDOUT_FILENO);
  if (status != MX_OK) {
    LOG(ERROR) << "launchpad_add_pipe failed: " << status;
    launchpad_destroy(lp);
    return false;
  }

  if (include_stderr)
    launchpad_clone_fd(lp, pipe_fd, STDERR_FILENO);
  else
    launchpad_clone_fd(lp, STDERR_FILENO, STDERR_FILENO);

  mx_handle_t proc;
  const char* errmsg;
  status = launchpad_go(lp, &proc, &errmsg);
  if (status != MX_OK) {
    LOG(ERROR) << "launchpad_go failed: " << errmsg << ", status=" << status;
    return false;
  }

  output->clear();
  for (;;) {
    char buffer[256];
    ssize_t bytes_read = read(pipe_fd, buffer, sizeof(buffer));
    if (bytes_read <= 0)
      break;
    output->append(buffer, bytes_read);
  }
  close(pipe_fd);

  Process process(proc);
  return process.WaitForExit(exit_code);
}

}  // namespace

Process LaunchProcess(const CommandLine& cmdline,
                      const LaunchOptions& options) {
  return LaunchProcess(cmdline.argv(), options);
}

Process LaunchProcess(const std::vector<std::string>& argv,
                      const LaunchOptions& options) {
  std::vector<const char*> argv_cstr;
  argv_cstr.reserve(argv.size() + 1);
  for (const auto& arg : argv)
    argv_cstr.push_back(arg.c_str());
  argv_cstr.push_back(nullptr);

  // Note that per launchpad.h, the intention is that launchpad_ functions are
  // used in a "builder" style. From launchpad_create() to launchpad_go() the
  // status is tracked in the launchpad_t object, and launchpad_go() reports on
  // the final status, and cleans up |lp| (assuming it was even created).
  launchpad_t* lp;
  launchpad_create(options.job_handle, argv_cstr[0], &lp);
  launchpad_load_from_file(lp, argv_cstr[0]);
  launchpad_set_args(lp, argv.size(), argv_cstr.data());

  uint32_t to_clone =
      LP_CLONE_MXIO_ROOT | LP_CLONE_MXIO_CWD | LP_CLONE_DEFAULT_JOB;

  std::unique_ptr<char* []> new_environ;
  char* const empty_environ = nullptr;
  char* const* old_environ = environ;
  if (options.clear_environ)
    old_environ = &empty_environ;
  if (!options.environ.empty())
    new_environ = AlterEnvironment(old_environ, options.environ);
  if (!options.environ.empty() || options.clear_environ)
    launchpad_set_environ(lp, new_environ.get());
  else
    to_clone |= LP_CLONE_ENVIRON;

  if (!options.fds_to_remap)
    to_clone |= LP_CLONE_MXIO_STDIO;
  launchpad_clone(lp, to_clone);

  if (options.fds_to_remap) {
    for (const auto& src_target : *options.fds_to_remap) {
      launchpad_clone_fd(lp, src_target.first, src_target.second);
    }
  }

  mx_handle_t proc;
  const char* errmsg;
  mx_status_t status = launchpad_go(lp, &proc, &errmsg);
  if (status != MX_OK) {
    LOG(ERROR) << "launchpad_go failed: " << errmsg << ", status=" << status;
    return Process();
  }

  return Process(proc);
}

bool GetAppOutput(const CommandLine& cl, std::string* output) {
  return GetAppOutput(cl.argv(), output);
}

bool GetAppOutput(const std::vector<std::string>& argv, std::string* output) {
  int exit_code;
  bool result = GetAppOutputInternal(argv, false, output, &exit_code);
  return result && exit_code == EXIT_SUCCESS;
}

bool GetAppOutputAndError(const CommandLine& cl, std::string* output) {
  return GetAppOutputAndError(cl.argv(), output);
}

bool GetAppOutputAndError(const std::vector<std::string>& argv,
                          std::string* output) {
  int exit_code;
  bool result = GetAppOutputInternal(argv, true, output, &exit_code);
  return result && exit_code == EXIT_SUCCESS;
}

bool GetAppOutputWithExitCode(const CommandLine& cl,
                              std::string* output,
                              int* exit_code) {
  bool result = GetAppOutputInternal(cl.argv(), false, output, exit_code);
  return result && *exit_code == EXIT_SUCCESS;
}

}  // namespace base
