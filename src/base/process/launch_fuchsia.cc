// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/launch.h"

#include <launchpad/launchpad.h>
#include <magenta/process.h>
#include <magenta/processargs.h>
#include <unistd.h>

#include "base/command_line.h"
#include "base/fuchsia/default_job.h"
#include "base/logging.h"

namespace base {

namespace {

bool GetAppOutputInternal(const CommandLine& cmd_line,
                          bool include_stderr,
                          std::string* output,
                          int* exit_code) {
  DCHECK(exit_code);

  LaunchOptions options;

  // LaunchProcess will automatically clone any stdio fd we do not explicitly
  // map.
  int pipe_fd[2];
  if (pipe(pipe_fd) < 0)
    return false;
  options.fds_to_remap.emplace_back(pipe_fd[1], STDOUT_FILENO);
  if (include_stderr)
    options.fds_to_remap.emplace_back(pipe_fd[1], STDERR_FILENO);

  Process process = LaunchProcess(cmd_line, options);
  close(pipe_fd[1]);
  if (!process.IsValid()) {
    close(pipe_fd[0]);
    return false;
  }

  output->clear();
  for (;;) {
    char buffer[256];
    ssize_t bytes_read = read(pipe_fd[0], buffer, sizeof(buffer));
    if (bytes_read <= 0)
      break;
    output->append(buffer, bytes_read);
  }
  close(pipe_fd[0]);

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
  launchpad_t* lp = nullptr;
  mx_handle_t job = options.job_handle != MX_HANDLE_INVALID ? options.job_handle
                                                            : GetDefaultJob();
  DCHECK_NE(MX_HANDLE_INVALID, job);

  launchpad_create(job, argv_cstr[0], &lp);
  launchpad_load_from_file(lp, argv_cstr[0]);
  launchpad_set_args(lp, argv.size(), argv_cstr.data());

  uint32_t to_clone = LP_CLONE_MXIO_NAMESPACE | LP_CLONE_DEFAULT_JOB;

  std::unique_ptr<char* []> new_environ;
  char* const empty_environ = nullptr;
  char* const* old_environ = environ;
  if (options.clear_environ)
    old_environ = &empty_environ;

  EnvironmentMap environ_modifications = options.environ;
  if (!options.current_directory.empty()) {
    environ_modifications["PWD"] = options.current_directory.value();
  } else {
    to_clone |= LP_CLONE_MXIO_CWD;
  }

  if (to_clone & LP_CLONE_DEFAULT_JOB) {
    // Override Fuchsia's built in default job cloning behavior with our own
    // logic which uses |job| instead of mx_job_default().
    // This logic is based on the launchpad implementation.
    mx_handle_t job_duplicate = MX_HANDLE_INVALID;
    mx_status_t status =
        mx_handle_duplicate(job, MX_RIGHT_SAME_RIGHTS, &job_duplicate);
    if (status != MX_OK) {
      LOG(ERROR) << "mx_handle_duplicate(job): "
                 << mx_status_get_string(status);
      return Process();
    }
    launchpad_add_handle(lp, job_duplicate, PA_HND(PA_JOB_DEFAULT, 0));
    to_clone &= ~LP_CLONE_DEFAULT_JOB;
  }

  if (!environ_modifications.empty())
    new_environ = AlterEnvironment(old_environ, environ_modifications);

  if (!environ_modifications.empty() || options.clear_environ)
    launchpad_set_environ(lp, new_environ.get());
  else
    to_clone |= LP_CLONE_ENVIRON;
  launchpad_clone(lp, to_clone);

  // Clone the mapped file-descriptors, plus any of the stdio descriptors
  // which were not explicitly specified.
  bool stdio_already_mapped[3] = {false};
  for (const auto& src_target : options.fds_to_remap) {
    if (static_cast<size_t>(src_target.second) <
        arraysize(stdio_already_mapped))
      stdio_already_mapped[src_target.second] = true;
    launchpad_clone_fd(lp, src_target.first, src_target.second);
  }
  for (size_t stdio_fd = 0; stdio_fd < arraysize(stdio_already_mapped);
       ++stdio_fd) {
    if (!stdio_already_mapped[stdio_fd])
      launchpad_clone_fd(lp, stdio_fd, stdio_fd);
  }

  for (const auto& id_and_handle : options.handles_to_transfer) {
    launchpad_add_handle(lp, id_and_handle.handle, id_and_handle.id);
  }

  mx_handle_t proc;
  const char* errmsg;
  mx_status_t status = launchpad_go(lp, &proc, &errmsg);
  if (status != MX_OK) {
    LOG(ERROR) << "launchpad_go failed: " << errmsg
               << ", status=" << mx_status_get_string(status);
    return Process();
  }

  return Process(proc);
}

bool GetAppOutput(const CommandLine& cl, std::string* output) {
  int exit_code;
  bool result = GetAppOutputInternal(cl, false, output, &exit_code);
  return result && exit_code == EXIT_SUCCESS;
}

bool GetAppOutput(const std::vector<std::string>& argv, std::string* output) {
  return GetAppOutput(CommandLine(argv), output);
}

bool GetAppOutputAndError(const CommandLine& cl, std::string* output) {
  int exit_code;
  bool result = GetAppOutputInternal(cl, true, output, &exit_code);
  return result && exit_code == EXIT_SUCCESS;
}

bool GetAppOutputAndError(const std::vector<std::string>& argv,
                          std::string* output) {
  return GetAppOutputAndError(CommandLine(argv), output);
}

bool GetAppOutputWithExitCode(const CommandLine& cl,
                              std::string* output,
                              int* exit_code) {
  // Contrary to GetAppOutput(), |true| return here means that the process was
  // launched and the exit code was waited upon successfully, but not
  // necessarily that the exit code was EXIT_SUCCESS.
  return GetAppOutputInternal(cl, false, output, exit_code);
}

}  // namespace base
