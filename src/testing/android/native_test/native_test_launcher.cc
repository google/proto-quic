// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This class sets up the environment for running the native tests inside an
// android application. It outputs (to a fifo) markers identifying the
// START/PASSED/CRASH of the test suite, FAILURE/SUCCESS of individual tests,
// etc.
// These markers are read by the test runner script to generate test results.
// It installs signal handlers to detect crashes.

#include <android/log.h>
#include <signal.h>

#include "base/android/base_jni_registrar.h"
#include "base/android/context_utils.h"
#include "base/android/jni_string.h"
#include "base/android/scoped_java_ref.h"
#include "base/at_exit.h"
#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "base/test/test_support_android.h"
#include "gtest/gtest.h"
#include "jni/NativeTest_jni.h"
#include "testing/android/native_test/main_runner.h"
#include "testing/android/native_test/native_test_util.h"

using base::android::JavaParamRef;

// The main function of the program to be wrapped as a test apk.
extern int main(int argc, char** argv);

namespace testing {
namespace android {

namespace {

const char kLogTag[] = "chromium";
const char kCrashedMarker[] = "[ CRASHED      ]\n";

// The list of signals which are considered to be crashes.
const int kExceptionSignals[] = {
  SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS, -1
};

struct sigaction g_old_sa[NSIG];

// This function runs in a compromised context. It should not allocate memory.
void SignalHandler(int sig, siginfo_t* info, void* reserved) {
  // Output the crash marker.
  write(STDOUT_FILENO, kCrashedMarker, sizeof(kCrashedMarker) - 1);
  g_old_sa[sig].sa_sigaction(sig, info, reserved);
}

// Writes printf() style string to Android's logger where |priority| is one of
// the levels defined in <android/log.h>.
void AndroidLog(int priority, const char* format, ...) {
  va_list args;
  va_start(args, format);
  __android_log_vprint(priority, kLogTag, format, args);
  va_end(args);
}

}  // namespace

static void RunTests(JNIEnv* env,
                     const JavaParamRef<jobject>& obj,
                     const JavaParamRef<jstring>& jcommand_line_flags,
                     const JavaParamRef<jstring>& jcommand_line_file_path,
                     const JavaParamRef<jstring>& jstdout_file_path,
                     const JavaParamRef<jobject>& app_context,
                     const JavaParamRef<jstring>& jtest_data_dir) {
  // Command line initialized basically, will be fully initialized later.
  static const char* const kInitialArgv[] = { "ChromeTestActivity" };
  base::CommandLine::Init(arraysize(kInitialArgv), kInitialArgv);

  std::vector<std::string> args;

  const std::string command_line_file_path(
      base::android::ConvertJavaStringToUTF8(env, jcommand_line_file_path));
  if (command_line_file_path.empty())
    args.push_back("_");
  else
    ParseArgsFromCommandLineFile(command_line_file_path.c_str(), &args);

  const std::string command_line_flags(
      base::android::ConvertJavaStringToUTF8(env, jcommand_line_flags));
  ParseArgsFromString(command_line_flags, &args);

  std::vector<char*> argv;
  int argc = ArgsToArgv(args, &argv);

  // Fully initialize command line with arguments.
  base::CommandLine::ForCurrentProcess()->AppendArguments(
      base::CommandLine(argc, &argv[0]), false);
  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();

  base::FilePath stdout_file_path(
      base::android::ConvertJavaStringToUTF8(env, jstdout_file_path));

  // A few options, such "--gtest_list_tests", will just use printf directly
  // Always redirect stdout to a known file.
  if (freopen(stdout_file_path.value().c_str(), "a+", stdout) == NULL) {
    AndroidLog(ANDROID_LOG_ERROR, "Failed to redirect stream to file: %s: %s\n",
               stdout_file_path.value().c_str(), strerror(errno));
    exit(EXIT_FAILURE);
  }
  dup2(STDOUT_FILENO, STDERR_FILENO);

  if (command_line.HasSwitch(switches::kWaitForDebugger)) {
    AndroidLog(ANDROID_LOG_VERBOSE,
               "Native test waiting for GDB because flag %s was supplied",
               switches::kWaitForDebugger);
    base::debug::WaitForDebugger(24 * 60 * 60, true);
  }

  base::FilePath test_data_dir(
      base::android::ConvertJavaStringToUTF8(env, jtest_data_dir));
  base::InitAndroidTestPaths(test_data_dir);

  ScopedMainEntryLogger scoped_main_entry_logger;
  main(argc, &argv[0]);
}

bool RegisterNativeTestJNI(JNIEnv* env) {
  if (!base::android::RegisterJni(env))
    return false;
  if (!RegisterMainRunnerJni(env))
    return false;
  return RegisterNativesImpl(env);
}

// TODO(nileshagrawal): now that we're using FIFO, test scripts can detect EOF.
// Remove the signal handlers.
void InstallHandlers() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));

  sa.sa_sigaction = SignalHandler;
  sa.sa_flags = SA_SIGINFO;

  for (unsigned int i = 0; kExceptionSignals[i] != -1; ++i) {
    sigaction(kExceptionSignals[i], &sa, &g_old_sa[kExceptionSignals[i]]);
  }
}

}  // namespace android
}  // namespace testing
