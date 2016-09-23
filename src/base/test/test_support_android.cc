// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdarg.h>
#include <string.h>

#include "base/android/path_utils.h"
#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/message_loop/message_loop.h"
#include "base/message_loop/message_pump_android.h"
#include "base/path_service.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/multiprocess_test.h"

namespace {

base::FilePath* g_test_data_dir = nullptr;

struct RunState {
  RunState(base::MessagePump::Delegate* delegate, int run_depth)
      : delegate(delegate),
        run_depth(run_depth),
        should_quit(false) {
  }

  base::MessagePump::Delegate* delegate;

  // Used to count how many Run() invocations are on the stack.
  int run_depth;

  // Used to flag that the current Run() invocation should return ASAP.
  bool should_quit;
};

RunState* g_state = NULL;

// A singleton WaitableEvent wrapper so we avoid a busy loop in
// MessagePumpForUIStub. Other platforms use the native event loop which blocks
// when there are no pending messages.
class Waitable {
 public:
  static Waitable* GetInstance() {
    return base::Singleton<Waitable,
                           base::LeakySingletonTraits<Waitable>>::get();
  }

  // Signals that there are more work to do.
  void Signal() { waitable_event_.Signal(); }

  // Blocks until more work is scheduled.
  void Block() { waitable_event_.Wait(); }

  void Quit() {
    g_state->should_quit = true;
    Signal();
  }

 private:
  friend struct base::DefaultSingletonTraits<Waitable>;

  Waitable()
      : waitable_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                        base::WaitableEvent::InitialState::NOT_SIGNALED) {}

  base::WaitableEvent waitable_event_;

  DISALLOW_COPY_AND_ASSIGN(Waitable);
};

// The MessagePumpForUI implementation for test purpose.
class MessagePumpForUIStub : public base::MessagePumpForUI {
  ~MessagePumpForUIStub() override {}

  void Start(base::MessagePump::Delegate* delegate) override {
    NOTREACHED() << "The Start() method shouldn't be called in test, using"
        " Run() method should be used.";
  }

  void Run(base::MessagePump::Delegate* delegate) override {
    // The following was based on message_pump_glib.cc, except we're using a
    // WaitableEvent since there are no native message loop to use.
    RunState state(delegate, g_state ? g_state->run_depth + 1 : 1);

    RunState* previous_state = g_state;
    g_state = &state;

    bool more_work_is_plausible = true;

    for (;;) {
      if (!more_work_is_plausible) {
        Waitable::GetInstance()->Block();
        if (g_state->should_quit)
          break;
      }

      more_work_is_plausible = g_state->delegate->DoWork();
      if (g_state->should_quit)
        break;

      base::TimeTicks delayed_work_time;
      more_work_is_plausible |=
          g_state->delegate->DoDelayedWork(&delayed_work_time);
      if (g_state->should_quit)
        break;

      if (more_work_is_plausible)
        continue;

      more_work_is_plausible = g_state->delegate->DoIdleWork();
      if (g_state->should_quit)
        break;

      more_work_is_plausible |= !delayed_work_time.is_null();
    }

    g_state = previous_state;
  }

  void Quit() override { Waitable::GetInstance()->Quit(); }

  void ScheduleWork() override { Waitable::GetInstance()->Signal(); }

  void ScheduleDelayedWork(const base::TimeTicks& delayed_work_time) override {
    Waitable::GetInstance()->Signal();
  }
};

std::unique_ptr<base::MessagePump> CreateMessagePumpForUIStub() {
  return std::unique_ptr<base::MessagePump>(new MessagePumpForUIStub());
};

// Provides the test path for DIR_SOURCE_ROOT and DIR_ANDROID_APP_DATA.
bool GetTestProviderPath(int key, base::FilePath* result) {
  switch (key) {
    // TODO(agrieve): Stop overriding DIR_ANDROID_APP_DATA.
    // https://crbug.com/617734
    case base::DIR_ANDROID_APP_DATA:
    case base::DIR_SOURCE_ROOT:
      CHECK(g_test_data_dir != nullptr);
      *result = *g_test_data_dir;
      return true;
    default:
      return false;
  }
}

void InitPathProvider(int key) {
  base::FilePath path;
  // If failed to override the key, that means the way has not been registered.
  if (GetTestProviderPath(key, &path) && !PathService::Override(key, path))
    PathService::RegisterProvider(&GetTestProviderPath, key, key + 1);
}

}  // namespace

namespace base {

void InitAndroidTestLogging() {
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  logging::InitLogging(settings);
  // To view log output with IDs and timestamps use "adb logcat -v threadtime".
  logging::SetLogItems(false,    // Process ID
                       false,    // Thread ID
                       false,    // Timestamp
                       false);   // Tick count
}

void InitAndroidTestPaths(const FilePath& test_data_dir) {
  if (g_test_data_dir) {
    CHECK(test_data_dir == *g_test_data_dir);
    return;
  }
  g_test_data_dir = new FilePath(test_data_dir);
  InitPathProvider(DIR_SOURCE_ROOT);
  InitPathProvider(DIR_ANDROID_APP_DATA);
}

void InitAndroidTestMessageLoop() {
  if (!MessageLoop::InitMessagePumpForUIFactory(&CreateMessagePumpForUIStub))
    LOG(INFO) << "MessagePumpForUIFactory already set, unable to override.";
}

void InitAndroidTest() {
  if (!base::AndroidIsChildProcess()) {
    InitAndroidTestLogging();
  }
  InitAndroidTestMessageLoop();
}
}  // namespace base
