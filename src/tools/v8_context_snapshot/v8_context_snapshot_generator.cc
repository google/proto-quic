// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/message_loop/message_loop.h"
#include "base/task_scheduler/task_scheduler.h"
#include "gin/v8_initializer.h"
#include "mojo/edk/embedder/embedder.h"
#include "third_party/WebKit/public/platform/WebThread.h"
#include "third_party/WebKit/public/web/WebKit.h"
#include "third_party/WebKit/public/web/WebV8ContextSnapshot.h"
#include "v8/include/v8.h"

namespace {

class SnapshotThread : public blink::WebThread {
 public:
  bool IsCurrentThread() const override { return true; }
  blink::WebScheduler* Scheduler() const override { return nullptr; }
  blink::WebTaskRunner* GetWebTaskRunner() override { return nullptr; }
};

class SnapshotPlatform final : public blink::Platform {
 public:
  bool IsTakingV8ContextSnapshot() override { return true; }
  blink::WebThread* CurrentThread() override {
    static SnapshotThread dummy_thread;
    return &dummy_thread;
  }
};

}  // namespace

// This program takes a snapshot of V8 contexts and writes it out as a file.
// The snapshot file is consumed by Blink.
//
// Usage:
// % v8_context_snapshot_generator --output_file=<filename>
int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  base::CommandLine::Init(argc, argv);
#ifdef V8_USE_EXTERNAL_STARTUP_DATA
  gin::V8Initializer::LoadV8Snapshot();
  gin::V8Initializer::LoadV8Natives();
#endif

  // Set up environment to make Blink and V8 workable.
  base::MessageLoop message_loop;
  base::TaskScheduler::CreateAndStartWithDefaultParams("TakeSnapshot");
  mojo::edk::Init();

  // Take a snapshot.
  SnapshotPlatform platform;
  blink::Initialize(&platform);
  v8::StartupData blob = blink::WebV8ContextSnapshot::TakeSnapshot();

  // Save the snapshot as a file. Filename is given in a command line option.
  base::FilePath file_path =
      base::CommandLine::ForCurrentProcess()->GetSwitchValuePath("output_file");
  CHECK(!file_path.empty());
  CHECK_LT(0, base::WriteFile(file_path, blob.data, blob.raw_size));

  delete[] blob.data;

  return 0;
}
