// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/synchronization/waitable_event_watcher.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/platform_thread.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

namespace {

// The message loops on which each waitable event timer should be tested.
const MessageLoop::Type testing_message_loops[] = {
  MessageLoop::TYPE_DEFAULT,
  MessageLoop::TYPE_IO,
#if !defined(OS_IOS)  // iOS does not allow direct running of the UI loop.
  MessageLoop::TYPE_UI,
#endif
};

const int kNumTestingMessageLoops = arraysize(testing_message_loops);

void QuitWhenSignaled(WaitableEvent* event) {
  MessageLoop::current()->QuitWhenIdle();
}

class DecrementCountContainer {
 public:
  explicit DecrementCountContainer(int* counter) : counter_(counter) {
  }
  void OnWaitableEventSignaled(WaitableEvent* object) {
    // NOTE: |object| may be already deleted.
    --(*counter_);
  }
 private:
  int* counter_;
};

void RunTest_BasicSignal(MessageLoop::Type message_loop_type) {
  MessageLoop message_loop(message_loop_type);

  // A manual-reset event that is not yet signaled.
  WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);

  WaitableEventWatcher watcher;
  watcher.StartWatching(&event, BindOnce(&QuitWhenSignaled));

  event.Signal();

  RunLoop().Run();
}

void RunTest_BasicCancel(MessageLoop::Type message_loop_type) {
  MessageLoop message_loop(message_loop_type);

  // A manual-reset event that is not yet signaled.
  WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);

  WaitableEventWatcher watcher;

  watcher.StartWatching(&event, BindOnce(&QuitWhenSignaled));

  watcher.StopWatching();
}

void RunTest_CancelAfterSet(MessageLoop::Type message_loop_type) {
  MessageLoop message_loop(message_loop_type);

  // A manual-reset event that is not yet signaled.
  WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);

  WaitableEventWatcher watcher;

  int counter = 1;
  DecrementCountContainer delegate(&counter);
  WaitableEventWatcher::EventCallback callback = BindOnce(
      &DecrementCountContainer::OnWaitableEventSignaled, Unretained(&delegate));
  watcher.StartWatching(&event, std::move(callback));

  event.Signal();

  // Let the background thread do its business
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(30));

  watcher.StopWatching();

  RunLoop().RunUntilIdle();

  // Our delegate should not have fired.
  EXPECT_EQ(1, counter);
}

void RunTest_OutlivesMessageLoop(MessageLoop::Type message_loop_type) {
  // Simulate a MessageLoop that dies before an WaitableEventWatcher.  This
  // ordinarily doesn't happen when people use the Thread class, but it can
  // happen when people use the Singleton pattern or atexit.
  WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);
  {
    WaitableEventWatcher watcher;
    {
      MessageLoop message_loop(message_loop_type);

      watcher.StartWatching(&event, BindOnce(&QuitWhenSignaled));
    }
  }
}

void RunTest_DeleteUnder(MessageLoop::Type message_loop_type,
                         bool delay_after_delete) {
  // Delete the WaitableEvent out from under the Watcher. This is explictly
  // allowed by the interface.

  MessageLoop message_loop(message_loop_type);

  {
    WaitableEventWatcher watcher;

    auto* event = new WaitableEvent(WaitableEvent::ResetPolicy::AUTOMATIC,
                                    WaitableEvent::InitialState::NOT_SIGNALED);

    watcher.StartWatching(event, BindOnce(&QuitWhenSignaled));

    if (delay_after_delete) {
      // On Windows that sleep() improves the chance to catch some problems.
      // It postpones the dtor |watcher| (which immediately cancel the waiting)
      // and gives some time to run to a created background thread.
      // Unfortunately, that thread is under OS control and we can't
      // manipulate it directly.
      base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(30));
    }

    delete event;
  }
}

void RunTest_SignalAndDelete(MessageLoop::Type message_loop_type,
                             bool delay_after_delete) {
  // Signal and immediately delete the WaitableEvent out from under the Watcher.

  MessageLoop message_loop(message_loop_type);

  {
    WaitableEventWatcher watcher;

    auto event = base::MakeUnique<WaitableEvent>(
        WaitableEvent::ResetPolicy::AUTOMATIC,
        WaitableEvent::InitialState::NOT_SIGNALED);

    watcher.StartWatching(event.get(), BindOnce(&QuitWhenSignaled));
    event->Signal();
    event.reset();

    if (delay_after_delete) {
      // On Windows that sleep() improves the chance to catch some problems.
      // It postpones the dtor |watcher| (which immediately cancel the waiting)
      // and gives some time to run to a created background thread.
      // Unfortunately, that thread is under OS control and we can't
      // manipulate it directly.
      base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(30));
    }

    // Wait for the watcher callback.
    RunLoop().Run();
  }
}

}  // namespace

//-----------------------------------------------------------------------------

TEST(WaitableEventWatcherTest, BasicSignal) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_BasicSignal(testing_message_loops[i]);
  }
}

TEST(WaitableEventWatcherTest, BasicCancel) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_BasicCancel(testing_message_loops[i]);
  }
}

TEST(WaitableEventWatcherTest, CancelAfterSet) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_CancelAfterSet(testing_message_loops[i]);
  }
}

TEST(WaitableEventWatcherTest, OutlivesMessageLoop) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_OutlivesMessageLoop(testing_message_loops[i]);
  }
}

TEST(WaitableEventWatcherTest, DeleteUnder) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_DeleteUnder(testing_message_loops[i], false);
    RunTest_DeleteUnder(testing_message_loops[i], true);
  }
}

TEST(WaitableEventWatcherTest, SignalAndDelete) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_SignalAndDelete(testing_message_loops[i], false);
    RunTest_SignalAndDelete(testing_message_loops[i], true);
  }
}

}  // namespace base
