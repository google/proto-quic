// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file provides a thin binary wrapper around the BattOr Agent
// library. This binary wrapper provides a means for non-C++ tracing
// controllers, such as Telemetry and Android Systrace, to issue high-level
// tracing commands to the BattOr through an interactive shell.
//
// Example usage of how an external trace controller might use this binary:
//
// 1) Telemetry's PowerTracingAgent is told to start recording power samples
// 2) PowerTracingAgent opens up a BattOr agent binary subprocess
// 3) PowerTracingAgent sends the subprocess the StartTracing message via
//    STDIN
// 4) PowerTracingAgent waits for the subprocess to write a line to STDOUT
//    ('Done.' if successful, some error message otherwise)
// 5) If the last command was successful, PowerTracingAgent waits for the
//    duration of the trace
// 6) When the tracing should end, PowerTracingAgent records the clock sync
//    start timestamp and sends the subprocess the
//    'RecordClockSyncMark <marker>' message via STDIN.
// 7) PowerTracingAgent waits for the subprocess to write a line to STDOUT
//    ('Done.' if successful, some error message otherwise)
// 8) If the last command was successful, PowerTracingAgent records the clock
//    sync end timestamp and sends the subprocess the StopTracing message via
//    STDIN
// 9) PowerTracingAgent continues to read trace output lines from STDOUT until
//    the binary exits with an exit code of 1 (indicating failure) or the
//    'Done.' line is printed to STDOUT, signaling the last line of the trace
// 10) PowerTracingAgent returns the battery trace to the Telemetry trace
//     controller

#include <stdint.h>

#include <fstream>
#include <iostream>

#include "base/at_exit.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/command_line.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "tools/battor_agent/battor_agent.h"
#include "tools/battor_agent/battor_error.h"
#include "tools/battor_agent/battor_finder.h"

using std::endl;

namespace battor {

namespace {

const char kIoThreadName[] = "BattOr IO Thread";
const char kFileThreadName[] = "BattOr File Thread";

const char kUsage[] =
    "Start the battor_agent shell with:\n"
    "\n"
    "  battor_agent <switches>\n"
    "\n"
    "Switches: \n"
    "  --battor-path=<path> Uses the specified BattOr path.\n"
    "\n"
    "Once in the shell, you can issue the following commands:\n"
    "\n"
    "  StartTracing\n"
    "  StopTracing <optional file path>\n"
    "  SupportsExplicitClockSync\n"
    "  RecordClockSyncMarker <marker>\n"
    "  Exit\n"
    "  Help\n"
    "\n";

void PrintSupportsExplicitClockSync() {
  std::cout << BattOrAgent::SupportsExplicitClockSync() << endl;
}

// Logs the error and exits with an error code.
void HandleError(battor::BattOrError error) {
  if (error != BATTOR_ERROR_NONE)
    LOG(FATAL) << "Fatal error when communicating with the BattOr: "
               << BattOrErrorToString(error);
}

// Prints an error message and exits due to a required thread failing to start.
void ExitFromThreadStartFailure(const std::string& thread_name) {
  LOG(FATAL) << "Failed to start " << thread_name;
}

std::vector<std::string> TokenizeString(std::string cmd) {
  base::StringTokenizer tokenizer(cmd, " ");
  std::vector<std::string> tokens;
  while (tokenizer.GetNext())
    tokens.push_back(tokenizer.token());
  return tokens;
}

}  // namespace

// Wrapper class containing all state necessary for an independent binary to
// use a BattOrAgent to communicate with a BattOr.
class BattOrAgentBin : public BattOrAgent::Listener {
 public:
  BattOrAgentBin() : io_thread_(kIoThreadName), file_thread_(kFileThreadName) {}

  ~BattOrAgentBin() { DCHECK(!agent_); }

  // Starts the interactive BattOr agent shell and eventually returns an exit
  // code.
  int Run(int argc, char* argv[]) {
    // If we don't have any BattOr to use, exit.
    std::string path = BattOrFinder::FindBattOr();
    if (path.empty()) {
      std::cout << "Unable to find a BattOr." << endl;
      exit(1);
    }

    SetUp(path);

    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&BattOrAgentBin::RunNextCommand, base::Unretained(this)));
    ui_thread_run_loop_.Run();

    TearDown();
    return 0;
  }

  // Performs any setup necessary for the BattOr binary to run.
  void SetUp(const std::string& path) {
    base::Thread::Options io_thread_options;
    io_thread_options.message_loop_type = base::MessageLoopForIO::TYPE_IO;
    if (!io_thread_.StartWithOptions(io_thread_options)) {
      ExitFromThreadStartFailure(kIoThreadName);
    }

    // Block until the creation of the BattOrAgent is complete. This doesn't
    // seem necessary because we're posting the creation to the IO thread
    // before posting any commands, so we're guaranteed that the creation
    // will happen first. However, the crashes that happen without this sync
    // mechanism in place say otherwise.
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    io_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::Bind(&BattOrAgentBin::CreateAgent, base::Unretained(this), path,
                   base::ThreadTaskRunnerHandle::Get(), &done));
    done.Wait();
  }

  // Performs any cleanup necessary after the BattOr binary is done running.
  void TearDown() {
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    io_thread_.task_runner()->PostTask(
        FROM_HERE, base::Bind(&BattOrAgentBin::DeleteAgent,
                              base::Unretained(this), &done));
    done.Wait();
  }

  void RunNextCommand() {
    std::string cmd;
    std::getline(std::cin, cmd);

    if (cmd == "StartTracing") {
      StartTracing();
    } else if (cmd.find("StopTracing") != std::string::npos) {
      std::vector<std::string> tokens = TokenizeString(cmd);

      if (tokens[0] != "StopTracing" || tokens.size() > 2) {
        std::cout << "Invalid StopTracing command." << endl;
        std::cout << kUsage << endl;
        PostRunNextCommand();
        return;
      }

      // tokens[1] contains the optional output file argument, which allows
      // users to dump the trace to a file instead instead of to STDOUT.
      std::string trace_output_file =
          tokens.size() == 2 ? tokens[1] : std::string();

      StopTracing(trace_output_file);
    } else if (cmd == "SupportsExplicitClockSync") {
      PrintSupportsExplicitClockSync();
      PostRunNextCommand();
    } else if (cmd.find("RecordClockSyncMarker") != std::string::npos) {
      std::vector<std::string> tokens = TokenizeString(cmd);
      if (tokens.size() != 2 || tokens[0] != "RecordClockSyncMarker") {
        std::cout << "Invalid RecordClockSyncMarker command." << endl;
        std::cout << kUsage << endl;
        PostRunNextCommand();
        return;
      }

      RecordClockSyncMarker(tokens[1]);
    } else if (cmd == "Exit" || std::cin.eof()) {
      ui_thread_message_loop_.task_runner()->PostTask(
          FROM_HERE, ui_thread_run_loop_.QuitClosure());
    } else {
      std::cout << kUsage << endl;
      PostRunNextCommand();
    }
  }

  void PostRunNextCommand() {
    ui_thread_message_loop_.task_runner()->PostTask(
        FROM_HERE,
        base::Bind(&BattOrAgentBin::RunNextCommand, base::Unretained(this)));
  }

  void StartTracing() {
    io_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::Bind(&BattOrAgent::StartTracing, base::Unretained(agent_.get())));
  }

  void OnStartTracingComplete(BattOrError error) override {
    if (error == BATTOR_ERROR_NONE)
      std::cout << "Done." << endl;
    else
      HandleError(error);

    PostRunNextCommand();
  }

  void StopTracing(const std::string& trace_output_file) {
    trace_output_file_ = trace_output_file;
    io_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::Bind(&BattOrAgent::StopTracing, base::Unretained(agent_.get())));
  }

  void OnStopTracingComplete(const std::string& trace,
                             BattOrError error) override {
    if (error == BATTOR_ERROR_NONE) {
      if (trace_output_file_.empty()) {
        std::cout << trace;
      } else {
        std::ofstream trace_stream(trace_output_file_);
        if (!trace_stream.is_open()) {
          std::cout << "Tracing output file could not be opened." << endl;
          exit(1);
        }
        trace_stream << trace;
        trace_stream.close();
      }
      std::cout << "Done." << endl;
    } else {
      HandleError(error);
    }

    ui_thread_message_loop_.task_runner()->PostTask(
        FROM_HERE, ui_thread_run_loop_.QuitClosure());
  }

  void RecordClockSyncMarker(const std::string& marker) {
    io_thread_.task_runner()->PostTask(
        FROM_HERE, base::Bind(&BattOrAgent::RecordClockSyncMarker,
                              base::Unretained(agent_.get()), marker));
  }

  void OnRecordClockSyncMarkerComplete(BattOrError error) override {
    if (error == BATTOR_ERROR_NONE)
      std::cout << "Done." << endl;
    else
      HandleError(error);

    PostRunNextCommand();
  }

  // Postable task for creating the BattOrAgent. Because the BattOrAgent has
  // uber thread safe dependencies, all interactions with it, including creating
  // and deleting it, MUST happen on the IO thread.
  void CreateAgent(
      const std::string& path,
      scoped_refptr<base::SingleThreadTaskRunner> ui_thread_task_runner,
      base::WaitableEvent* done) {
    // In Chrome, we already have a file thread running. Because the Chrome
    // serial library relies on having it available, we have to spin up our own.
    if (!file_thread_.Start())
      ExitFromThreadStartFailure(kFileThreadName);

    agent_.reset(new BattOrAgent(path, this, file_thread_.task_runner(),
                                 ui_thread_task_runner));
    done->Signal();
  }

  // Postable task for deleting the BattOrAgent. See the comment for
  // CreateAgent() above regarding why this is necessary.
  void DeleteAgent(base::WaitableEvent* done) {
    agent_.reset();
    done->Signal();
  }

 private:
  // NOTE: ui_thread_message_loop_ must appear before ui_thread_run_loop_ here
  // because ui_thread_run_loop_ checks for the current MessageLoop during
  // initialization.
  base::MessageLoopForUI ui_thread_message_loop_;
  base::RunLoop ui_thread_run_loop_;

  // Threads needed for serial communication.
  base::Thread io_thread_;
  base::Thread file_thread_;

  // The agent capable of asynchronously communicating with the BattOr.
  std::unique_ptr<BattOrAgent> agent_;

  std::string trace_output_file_;
};

}  // namespace battor

int main(int argc, char* argv[]) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  battor::BattOrAgentBin bin;
  return bin.Run(argc, argv);
}
