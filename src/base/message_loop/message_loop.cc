// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/message_loop/message_loop.h"

#include <algorithm>
#include <utility>

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_pump_default.h"
#include "base/run_loop.h"
#include "base/third_party/dynamic_annotations/dynamic_annotations.h"
#include "base/threading/thread_id_name_manager.h"
#include "base/threading/thread_local.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/trace_event.h"

#if defined(OS_MACOSX)
#include "base/message_loop/message_pump_mac.h"
#endif
#if defined(OS_POSIX) && !defined(OS_IOS)
#include "base/message_loop/message_pump_libevent.h"
#endif
#if defined(OS_ANDROID)
#include "base/message_loop/message_pump_android.h"
#endif
#if defined(USE_GLIB)
#include "base/message_loop/message_pump_glib.h"
#endif

namespace base {

namespace {

// A lazily created thread local storage for quick access to a thread's message
// loop, if one exists.
base::ThreadLocalPointer<MessageLoop>* GetTLSMessageLoop() {
  static auto* lazy_tls_ptr = new base::ThreadLocalPointer<MessageLoop>();
  return lazy_tls_ptr;
}
MessageLoop::MessagePumpFactory* message_pump_for_ui_factory_ = NULL;

#if defined(OS_IOS)
typedef MessagePumpIOSForIO MessagePumpForIO;
#elif defined(OS_NACL_SFI)
typedef MessagePumpDefault MessagePumpForIO;
#elif defined(OS_POSIX)
typedef MessagePumpLibevent MessagePumpForIO;
#endif

#if !defined(OS_NACL_SFI)
MessagePumpForIO* ToPumpIO(MessagePump* pump) {
  return static_cast<MessagePumpForIO*>(pump);
}
#endif  // !defined(OS_NACL_SFI)

std::unique_ptr<MessagePump> ReturnPump(std::unique_ptr<MessagePump> pump) {
  return pump;
}

}  // namespace

//------------------------------------------------------------------------------

MessageLoop::TaskObserver::TaskObserver() {
}

MessageLoop::TaskObserver::~TaskObserver() {
}

MessageLoop::DestructionObserver::~DestructionObserver() {
}

MessageLoop::NestingObserver::~NestingObserver() {}

//------------------------------------------------------------------------------

MessageLoop::MessageLoop(Type type)
    : MessageLoop(type, MessagePumpFactoryCallback()) {
  BindToCurrentThread();
}

MessageLoop::MessageLoop(std::unique_ptr<MessagePump> pump)
    : MessageLoop(TYPE_CUSTOM, Bind(&ReturnPump, Passed(&pump))) {
  BindToCurrentThread();
}

MessageLoop::~MessageLoop() {
  // If |pump_| is non-null, this message loop has been bound and should be the
  // current one on this thread. Otherwise, this loop is being destructed before
  // it was bound to a thread, so a different message loop (or no loop at all)
  // may be current.
  DCHECK((pump_ && current() == this) || (!pump_ && current() != this));

  // iOS just attaches to the loop, it doesn't Run it.
  // TODO(stuartmorgan): Consider wiring up a Detach().
#if !defined(OS_IOS)
  DCHECK(!run_loop_);
#endif

#if defined(OS_WIN)
  if (in_high_res_mode_)
    Time::ActivateHighResolutionTimer(false);
#endif
  // Clean up any unprocessed tasks, but take care: deleting a task could
  // result in the addition of more tasks (e.g., via DeleteSoon).  We set a
  // limit on the number of times we will allow a deleted task to generate more
  // tasks.  Normally, we should only pass through this loop once or twice.  If
  // we end up hitting the loop limit, then it is probably due to one task that
  // is being stubborn.  Inspect the queues to see who is left.
  bool did_work;
  for (int i = 0; i < 100; ++i) {
    DeletePendingTasks();
    ReloadWorkQueue();
    // If we end up with empty queues, then break out of the loop.
    did_work = DeletePendingTasks();
    if (!did_work)
      break;
  }
  DCHECK(!did_work);

  // Let interested parties have one last shot at accessing this.
  for (auto& observer : destruction_observers_)
    observer.WillDestroyCurrentMessageLoop();

  thread_task_runner_handle_.reset();

  // Tell the incoming queue that we are dying.
  incoming_task_queue_->WillDestroyCurrentMessageLoop();
  incoming_task_queue_ = NULL;
  unbound_task_runner_ = NULL;
  task_runner_ = NULL;

  // OK, now make it so that no one can find us.
  if (current() == this)
    GetTLSMessageLoop()->Set(nullptr);
}

// static
MessageLoop* MessageLoop::current() {
  // TODO(darin): sadly, we cannot enable this yet since people call us even
  // when they have no intention of using us.
  // DCHECK(loop) << "Ouch, did you forget to initialize me?";
  return GetTLSMessageLoop()->Get();
}

// static
bool MessageLoop::InitMessagePumpForUIFactory(MessagePumpFactory* factory) {
  if (message_pump_for_ui_factory_)
    return false;

  message_pump_for_ui_factory_ = factory;
  return true;
}

// static
std::unique_ptr<MessagePump> MessageLoop::CreateMessagePumpForType(Type type) {
// TODO(rvargas): Get rid of the OS guards.
#if defined(USE_GLIB) && !defined(OS_NACL)
  typedef MessagePumpGlib MessagePumpForUI;
#elif (defined(OS_LINUX) && !defined(OS_NACL)) || defined(OS_BSD)
  typedef MessagePumpLibevent MessagePumpForUI;
#endif

#if defined(OS_IOS) || defined(OS_MACOSX)
#define MESSAGE_PUMP_UI std::unique_ptr<MessagePump>(MessagePumpMac::Create())
#elif defined(OS_NACL)
// Currently NaCl doesn't have a UI MessageLoop.
// TODO(abarth): Figure out if we need this.
#define MESSAGE_PUMP_UI std::unique_ptr<MessagePump>()
#else
#define MESSAGE_PUMP_UI std::unique_ptr<MessagePump>(new MessagePumpForUI())
#endif

#if defined(OS_MACOSX)
  // Use an OS native runloop on Mac to support timer coalescing.
#define MESSAGE_PUMP_DEFAULT \
  std::unique_ptr<MessagePump>(new MessagePumpCFRunLoop())
#else
#define MESSAGE_PUMP_DEFAULT \
  std::unique_ptr<MessagePump>(new MessagePumpDefault())
#endif

  if (type == MessageLoop::TYPE_UI) {
    if (message_pump_for_ui_factory_)
      return message_pump_for_ui_factory_();
    return MESSAGE_PUMP_UI;
  }
  if (type == MessageLoop::TYPE_IO)
    return std::unique_ptr<MessagePump>(new MessagePumpForIO());

#if defined(OS_ANDROID)
  if (type == MessageLoop::TYPE_JAVA)
    return std::unique_ptr<MessagePump>(new MessagePumpForUI());
#endif

  DCHECK_EQ(MessageLoop::TYPE_DEFAULT, type);
  return MESSAGE_PUMP_DEFAULT;
}

void MessageLoop::AddDestructionObserver(
    DestructionObserver* destruction_observer) {
  DCHECK_EQ(this, current());
  destruction_observers_.AddObserver(destruction_observer);
}

void MessageLoop::RemoveDestructionObserver(
    DestructionObserver* destruction_observer) {
  DCHECK_EQ(this, current());
  destruction_observers_.RemoveObserver(destruction_observer);
}

void MessageLoop::AddNestingObserver(NestingObserver* observer) {
  DCHECK_EQ(this, current());
  CHECK(allow_nesting_);
  nesting_observers_.AddObserver(observer);
}

void MessageLoop::RemoveNestingObserver(NestingObserver* observer) {
  DCHECK_EQ(this, current());
  CHECK(allow_nesting_);
  nesting_observers_.RemoveObserver(observer);
}

void MessageLoop::QuitWhenIdle() {
  DCHECK_EQ(this, current());
  if (run_loop_) {
    run_loop_->QuitWhenIdle();
  } else {
    NOTREACHED() << "Must be inside Run to call QuitWhenIdle";
  }
}

void MessageLoop::QuitNow() {
  DCHECK_EQ(this, current());
  if (run_loop_) {
    pump_->Quit();
  } else {
    NOTREACHED() << "Must be inside Run to call Quit";
  }
}

bool MessageLoop::IsType(Type type) const {
  return type_ == type;
}

static void QuitCurrentWhenIdle() {
  MessageLoop::current()->QuitWhenIdle();
}

// static
Closure MessageLoop::QuitWhenIdleClosure() {
  return Bind(&QuitCurrentWhenIdle);
}

void MessageLoop::SetNestableTasksAllowed(bool allowed) {
  if (allowed) {
    CHECK(allow_nesting_);

    // Kick the native pump just in case we enter a OS-driven nested message
    // loop.
    pump_->ScheduleWork();
  }
  nestable_tasks_allowed_ = allowed;
}

bool MessageLoop::NestableTasksAllowed() const {
  return nestable_tasks_allowed_;
}

bool MessageLoop::IsNested() {
  return run_loop_->run_depth_ > 1;
}

void MessageLoop::AddTaskObserver(TaskObserver* task_observer) {
  DCHECK_EQ(this, current());
  CHECK(allow_task_observers_);
  task_observers_.AddObserver(task_observer);
}

void MessageLoop::RemoveTaskObserver(TaskObserver* task_observer) {
  DCHECK_EQ(this, current());
  CHECK(allow_task_observers_);
  task_observers_.RemoveObserver(task_observer);
}

bool MessageLoop::is_running() const {
  DCHECK_EQ(this, current());
  return run_loop_ != NULL;
}

bool MessageLoop::HasHighResolutionTasks() {
  return incoming_task_queue_->HasHighResolutionTasks();
}

bool MessageLoop::IsIdleForTesting() {
  // We only check the incoming queue, since we don't want to lock the work
  // queue.
  return incoming_task_queue_->IsIdleForTesting();
}

//------------------------------------------------------------------------------

// static
std::unique_ptr<MessageLoop> MessageLoop::CreateUnbound(
    Type type,
    MessagePumpFactoryCallback pump_factory) {
  return WrapUnique(new MessageLoop(type, pump_factory));
}

MessageLoop::MessageLoop(Type type, MessagePumpFactoryCallback pump_factory)
    : type_(type),
#if defined(OS_WIN)
      pending_high_res_tasks_(0),
      in_high_res_mode_(false),
#endif
      nestable_tasks_allowed_(true),
      pump_factory_(pump_factory),
      run_loop_(nullptr),
      current_pending_task_(nullptr),
      incoming_task_queue_(new internal::IncomingTaskQueue(this)),
      unbound_task_runner_(
          new internal::MessageLoopTaskRunner(incoming_task_queue_)),
      task_runner_(unbound_task_runner_),
      thread_id_(kInvalidThreadId) {
  // If type is TYPE_CUSTOM non-null pump_factory must be given.
  DCHECK(type_ != TYPE_CUSTOM || !pump_factory_.is_null());
}

void MessageLoop::BindToCurrentThread() {
  DCHECK(!pump_);
  if (!pump_factory_.is_null())
    pump_ = pump_factory_.Run();
  else
    pump_ = CreateMessagePumpForType(type_);

  DCHECK(!current()) << "should only have one message loop per thread";
  GetTLSMessageLoop()->Set(this);

  incoming_task_queue_->StartScheduling();
  unbound_task_runner_->BindToCurrentThread();
  unbound_task_runner_ = nullptr;
  SetThreadTaskRunnerHandle();
  thread_id_ = PlatformThread::CurrentId();
}

std::string MessageLoop::GetThreadName() const {
  DCHECK_NE(kInvalidThreadId, thread_id_)
      << "GetThreadName() must only be called after BindToCurrentThread()'s "
      << "side-effects have been synchronized with this thread.";
  return ThreadIdNameManager::GetInstance()->GetName(thread_id_);
}

void MessageLoop::SetTaskRunner(
    scoped_refptr<SingleThreadTaskRunner> task_runner) {
  DCHECK_EQ(this, current());
  DCHECK(task_runner);
  DCHECK(task_runner->BelongsToCurrentThread());
  DCHECK(!unbound_task_runner_);
  task_runner_ = std::move(task_runner);
  SetThreadTaskRunnerHandle();
}

void MessageLoop::ClearTaskRunnerForTesting() {
  DCHECK_EQ(this, current());
  DCHECK(!unbound_task_runner_);
  task_runner_ = nullptr;
  thread_task_runner_handle_.reset();
}

void MessageLoop::SetThreadTaskRunnerHandle() {
  DCHECK_EQ(this, current());
  // Clear the previous thread task runner first, because only one can exist at
  // a time.
  thread_task_runner_handle_.reset();
  thread_task_runner_handle_.reset(new ThreadTaskRunnerHandle(task_runner_));
}

void MessageLoop::RunHandler() {
  DCHECK_EQ(this, current());
  DCHECK(run_loop_);
  CHECK(allow_nesting_ || run_loop_->run_depth_ == 1);
  pump_->Run(this);
}

bool MessageLoop::ProcessNextDelayedNonNestableTask() {
  if (run_loop_->run_depth_ != 1)
    return false;

  if (deferred_non_nestable_work_queue_.empty())
    return false;

  PendingTask pending_task =
      std::move(deferred_non_nestable_work_queue_.front());
  deferred_non_nestable_work_queue_.pop();

  RunTask(&pending_task);
  return true;
}

void MessageLoop::RunTask(PendingTask* pending_task) {
  DCHECK(nestable_tasks_allowed_);
  current_pending_task_ = pending_task;

#if defined(OS_WIN)
  if (pending_task->is_high_res) {
    pending_high_res_tasks_--;
    CHECK_GE(pending_high_res_tasks_, 0);
  }
#endif

  // Execute the task and assume the worst: It is probably not reentrant.
  nestable_tasks_allowed_ = false;

  TRACE_TASK_EXECUTION("MessageLoop::RunTask", *pending_task);

  for (auto& observer : task_observers_)
    observer.WillProcessTask(*pending_task);
  task_annotator_.RunTask("MessageLoop::PostTask", pending_task);
  for (auto& observer : task_observers_)
    observer.DidProcessTask(*pending_task);

  nestable_tasks_allowed_ = true;

  current_pending_task_ = nullptr;
}

bool MessageLoop::DeferOrRunPendingTask(PendingTask pending_task) {
  if (pending_task.nestable || run_loop_->run_depth_ == 1) {
    RunTask(&pending_task);
    // Show that we ran a task (Note: a new one might arrive as a
    // consequence!).
    return true;
  }

  // We couldn't run the task now because we're in a nested message loop
  // and the task isn't nestable.
  deferred_non_nestable_work_queue_.push(std::move(pending_task));
  return false;
}

void MessageLoop::AddToDelayedWorkQueue(PendingTask pending_task) {
  // Move to the delayed work queue.
  delayed_work_queue_.push(std::move(pending_task));
}

bool MessageLoop::DeletePendingTasks() {
  bool did_work = !work_queue_.empty();
  while (!work_queue_.empty()) {
    PendingTask pending_task = std::move(work_queue_.front());
    work_queue_.pop();
    if (!pending_task.delayed_run_time.is_null()) {
      // We want to delete delayed tasks in the same order in which they would
      // normally be deleted in case of any funny dependencies between delayed
      // tasks.
      AddToDelayedWorkQueue(std::move(pending_task));
    }
  }
  did_work |= !deferred_non_nestable_work_queue_.empty();
  while (!deferred_non_nestable_work_queue_.empty()) {
    deferred_non_nestable_work_queue_.pop();
  }
  did_work |= !delayed_work_queue_.empty();

  // Historically, we always delete the task regardless of valgrind status. It's
  // not completely clear why we want to leak them in the loops above.  This
  // code is replicating legacy behavior, and should not be considered
  // absolutely "correct" behavior.  See TODO above about deleting all tasks
  // when it's safe.
  while (!delayed_work_queue_.empty()) {
    delayed_work_queue_.pop();
  }
  return did_work;
}

void MessageLoop::ReloadWorkQueue() {
  // We can improve performance of our loading tasks from the incoming queue to
  // |*work_queue| by waiting until the last minute (|*work_queue| is empty) to
  // load. That reduces the number of locks-per-task significantly when our
  // queues get large.
  if (work_queue_.empty()) {
#if defined(OS_WIN)
    pending_high_res_tasks_ +=
        incoming_task_queue_->ReloadWorkQueue(&work_queue_);
#else
    incoming_task_queue_->ReloadWorkQueue(&work_queue_);
#endif
  }
}

void MessageLoop::ScheduleWork() {
  pump_->ScheduleWork();
}

void MessageLoop::NotifyBeginNestedLoop() {
  for (auto& observer : nesting_observers_)
    observer.OnBeginNestedMessageLoop();
}

bool MessageLoop::DoWork() {
  if (!nestable_tasks_allowed_) {
    // Task can't be executed right now.
    return false;
  }

  for (;;) {
    ReloadWorkQueue();
    if (work_queue_.empty())
      break;

    // Execute oldest task.
    do {
      PendingTask pending_task = std::move(work_queue_.front());
      work_queue_.pop();
      if (!pending_task.delayed_run_time.is_null()) {
        int sequence_num = pending_task.sequence_num;
        TimeTicks delayed_run_time = pending_task.delayed_run_time;
        AddToDelayedWorkQueue(std::move(pending_task));
        // If we changed the topmost task, then it is time to reschedule.
        if (delayed_work_queue_.top().sequence_num == sequence_num)
          pump_->ScheduleDelayedWork(delayed_run_time);
      } else {
        if (DeferOrRunPendingTask(std::move(pending_task)))
          return true;
      }
    } while (!work_queue_.empty());
  }

  // Nothing happened.
  return false;
}

bool MessageLoop::DoDelayedWork(TimeTicks* next_delayed_work_time) {
  if (!nestable_tasks_allowed_ || delayed_work_queue_.empty()) {
    recent_time_ = *next_delayed_work_time = TimeTicks();
    return false;
  }

  // When we "fall behind", there will be a lot of tasks in the delayed work
  // queue that are ready to run.  To increase efficiency when we fall behind,
  // we will only call Time::Now() intermittently, and then process all tasks
  // that are ready to run before calling it again.  As a result, the more we
  // fall behind (and have a lot of ready-to-run delayed tasks), the more
  // efficient we'll be at handling the tasks.

  TimeTicks next_run_time = delayed_work_queue_.top().delayed_run_time;
  if (next_run_time > recent_time_) {
    recent_time_ = TimeTicks::Now();  // Get a better view of Now();
    if (next_run_time > recent_time_) {
      *next_delayed_work_time = next_run_time;
      return false;
    }
  }

  PendingTask pending_task =
      std::move(const_cast<PendingTask&>(delayed_work_queue_.top()));
  delayed_work_queue_.pop();

  if (!delayed_work_queue_.empty())
    *next_delayed_work_time = delayed_work_queue_.top().delayed_run_time;

  return DeferOrRunPendingTask(std::move(pending_task));
}

bool MessageLoop::DoIdleWork() {
  if (ProcessNextDelayedNonNestableTask())
    return true;

  if (run_loop_->quit_when_idle_received_)
    pump_->Quit();

  // When we return we will do a kernel wait for more tasks.
#if defined(OS_WIN)
  // On Windows we activate the high resolution timer so that the wait
  // _if_ triggered by the timer happens with good resolution. If we don't
  // do this the default resolution is 15ms which might not be acceptable
  // for some tasks.
  bool high_res = pending_high_res_tasks_ > 0;
  if (high_res != in_high_res_mode_) {
    in_high_res_mode_ = high_res;
    Time::ActivateHighResolutionTimer(in_high_res_mode_);
  }
#endif
  return false;
}

#if !defined(OS_NACL)
//------------------------------------------------------------------------------
// MessageLoopForUI

MessageLoopForUI::MessageLoopForUI(std::unique_ptr<MessagePump> pump)
    : MessageLoop(TYPE_UI, Bind(&ReturnPump, Passed(&pump))) {}

#if defined(OS_ANDROID)
void MessageLoopForUI::Start() {
  // No Histogram support for UI message loop as it is managed by Java side
  static_cast<MessagePumpForUI*>(pump_.get())->Start(this);
}

void MessageLoopForUI::StartForTesting(
    base::android::JavaMessageHandlerFactory* factory,
    WaitableEvent* test_done_event) {
  // No Histogram support for UI message loop as it is managed by Java side
  static_cast<MessagePumpForUI*>(pump_.get())
      ->StartForUnitTest(this, factory, test_done_event);
}

void MessageLoopForUI::Abort() {
  static_cast<MessagePumpForUI*>(pump_.get())->Abort();
}
#endif

#if defined(OS_IOS)
void MessageLoopForUI::Attach() {
  static_cast<MessagePumpUIApplication*>(pump_.get())->Attach(this);
}
#endif

#if defined(USE_OZONE) || (defined(USE_X11) && !defined(USE_GLIB))
bool MessageLoopForUI::WatchFileDescriptor(
    int fd,
    bool persistent,
    MessagePumpLibevent::Mode mode,
    MessagePumpLibevent::FileDescriptorWatcher *controller,
    MessagePumpLibevent::Watcher *delegate) {
  return static_cast<MessagePumpLibevent*>(pump_.get())->WatchFileDescriptor(
      fd,
      persistent,
      mode,
      controller,
      delegate);
}
#endif

#endif  // !defined(OS_NACL)

//------------------------------------------------------------------------------
// MessageLoopForIO

#if !defined(OS_NACL_SFI)

#if defined(OS_WIN)
void MessageLoopForIO::RegisterIOHandler(HANDLE file, IOHandler* handler) {
  ToPumpIO(pump_.get())->RegisterIOHandler(file, handler);
}

bool MessageLoopForIO::RegisterJobObject(HANDLE job, IOHandler* handler) {
  return ToPumpIO(pump_.get())->RegisterJobObject(job, handler);
}

bool MessageLoopForIO::WaitForIOCompletion(DWORD timeout, IOHandler* filter) {
  return ToPumpIO(pump_.get())->WaitForIOCompletion(timeout, filter);
}
#elif defined(OS_POSIX)
bool MessageLoopForIO::WatchFileDescriptor(int fd,
                                           bool persistent,
                                           Mode mode,
                                           FileDescriptorWatcher* controller,
                                           Watcher* delegate) {
  return ToPumpIO(pump_.get())->WatchFileDescriptor(
      fd,
      persistent,
      mode,
      controller,
      delegate);
}
#endif

#endif  // !defined(OS_NACL_SFI)

}  // namespace base
