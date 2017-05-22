// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_RUN_LOOP_H_
#define BASE_RUN_LOOP_H_

#include <stack>
#include <vector>

#include "base/base_export.h"
#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "base/sequence_checker.h"
#include "base/threading/thread_checker.h"
#include "build/build_config.h"

namespace base {
#if defined(OS_ANDROID)
class MessagePumpForUI;
#endif

#if defined(OS_IOS)
class MessagePumpUIApplication;
#endif

class SingleThreadTaskRunner;

// Helper class to run the RunLoop::Delegate associated with the current thread.
// A RunLoop::Delegate must have been bound to this thread (ref.
// RunLoop::RegisterDelegateForCurrentThread()) prior to using any of RunLoop's
// member and static methods unless explicitly indicated otherwise (e.g.
// IsRunning/IsNestedOnCurrentThread()). RunLoop::Run can only be called once
// per RunLoop lifetime. Create a RunLoop on the stack and call Run/Quit to run
// a nested RunLoop but please do not use nested loops in production code!
class BASE_EXPORT RunLoop {
 public:
  RunLoop();
  ~RunLoop();

  // Run the current RunLoop::Delegate. This blocks until Quit is called. Before
  // calling Run, be sure to grab the QuitClosure in order to stop the
  // RunLoop::Delegate asynchronously. MessageLoop::QuitWhenIdle and QuitNow
  // will also trigger a return from Run (if RunLoop::Delegate happens to be a
  // MessageLoop...), but those are deprecated.
  void Run();

  // Run the current RunLoop::Delegate until it doesn't find any tasks or
  // messages in its queue (it goes idle). WARNING: This may never return! Only
  // use this when repeating tasks such as animated web pages have been shut
  // down.
  void RunUntilIdle();

  bool running() const {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    return running_;
  }

  // Quit() quits an earlier call to Run() immediately. QuitWhenIdle() quits an
  // earlier call to Run() when there aren't any tasks or messages in the queue.
  //
  // These methods are thread-safe but note that Quit() is best-effort when
  // called from another thread (will quit soon but tasks that were already
  // queued on this RunLoop will get to run first).
  //
  // There can be other nested RunLoops servicing the same task queue
  // (MessageLoop); Quitting one RunLoop has no bearing on the others. Quit()
  // and QuitWhenIdle() can be called before, during or after Run(). If called
  // before Run(), Run() will return immediately when called. Calling Quit() or
  // QuitWhenIdle() after the RunLoop has already finished running has no
  // effect.
  //
  // WARNING: You must NEVER assume that a call to Quit() or QuitWhenIdle() will
  // terminate the targetted message loop. If a nested run loop continues
  // running, the target may NEVER terminate. It is very easy to livelock (run
  // forever) in such a case.
  void Quit();
  void QuitWhenIdle();

  // Convenience methods to get a closure that safely calls Quit() or
  // QuitWhenIdle() (has no effect if the RunLoop instance is gone).
  //
  // The resulting Closure is thread-safe (note however that invoking the
  // QuitClosure() from another thread than this RunLoop's will result in an
  // asynchronous rather than immediate Quit()).
  //
  // Example:
  //   RunLoop run_loop;
  //   PostTask(run_loop.QuitClosure());
  //   run_loop.Run();
  base::Closure QuitClosure();
  base::Closure QuitWhenIdleClosure();

  // Returns true if there is an active RunLoop on this thread.
  // Safe to call before RegisterDelegateForCurrentThread().
  static bool IsRunningOnCurrentThread();

  // Returns true if there is an active RunLoop on this thread and it's nested
  // within another active RunLoop.
  // Safe to call before RegisterDelegateForCurrentThread().
  static bool IsNestedOnCurrentThread();

  // A NestingObserver is notified when a nested run loop begins. The observers
  // are notified before the current thread's RunLoop::Delegate::Run() is
  // invoked and nested work begins.
  class BASE_EXPORT NestingObserver {
   public:
    virtual void OnBeginNestedRunLoop() = 0;

   protected:
    virtual ~NestingObserver() = default;
  };

  static void AddNestingObserverOnCurrentThread(NestingObserver* observer);
  static void RemoveNestingObserverOnCurrentThread(NestingObserver* observer);

  // Returns true if nesting is allowed on this thread.
  static bool IsNestingAllowedOnCurrentThread();

  // Disallow nesting. After this is called, running a nested RunLoop or calling
  // Add/RemoveNestingObserverOnCurrentThread() on this thread will crash.
  static void DisallowNestingOnCurrentThread();

  // A RunLoop::Delegate is a generic interface that allows RunLoop to be
  // separate from the uderlying implementation of the message loop for this
  // thread. It holds private state used by RunLoops on its associated thread.
  // One and only one RunLoop::Delegate must be registered on a given thread
  // via RunLoop::RegisterDelegateForCurrentThread() before RunLoop instances
  // and RunLoop static methods can be used on it.
  class BASE_EXPORT Delegate {
   protected:
    Delegate();
    ~Delegate();

    // The client interface provided back to the caller who registers this
    // Delegate via RegisterDelegateForCurrentThread.
    class Client {
     public:
      // Returns the RunLoop with the topmost active Run() call on the stack.
      // TODO(gab): Break the inter-dependency between MessageLoop and RunLoop
      // further. http://crbug.com/703346
      RunLoop* GetTopMostRunLoop() const;

      // Returns true if this |outer_| is currently in nested runs. This is a
      // shortcut for RunLoop::IsNestedOnCurrentThread() for the owner of this
      // interface.
      // TODO(gab): consider getting rid of this and the Client class altogether
      // when it's the only method left on Client. http://crbug.com/703346.
      bool IsNested() const;

     private:
      // Only a Delegate can instantiate a Delegate::Client.
      friend class Delegate;
      Client(Delegate* outer);

      Delegate* outer_;
    };

   private:
    // While the state is owned by the Delegate subclass, only RunLoop can use
    // it.
    friend class RunLoop;

    // Used by RunLoop to inform its Delegate to Run/Quit. Implementations are
    // expected to keep on running synchronously from the Run() call until the
    // eventual matching Quit() call. Upon receiving a Quit() call it should
    // return from the Run() call as soon as possible without executing
    // remaining tasks/messages. Run() calls can nest in which case each Quit()
    // call should result in the topmost active Run() call returning.
    virtual void Run() = 0;
    virtual void Quit() = 0;

    // A vector-based stack is more memory efficient than the default
    // deque-based stack as the active RunLoop stack isn't expected to ever
    // have more than a few entries.
    using RunLoopStack = std::stack<RunLoop*, std::vector<RunLoop*>>;

    bool allow_nesting_ = true;
    RunLoopStack active_run_loops_;
    ObserverList<RunLoop::NestingObserver> nesting_observers_;

    // True once this Delegate is bound to a thread via
    // RegisterDelegateForCurrentThread().
    bool bound_ = false;

    // Thread-affine per its use of TLS.
    THREAD_CHECKER(bound_thread_checker_);

    Client client_interface_ = Client(this);

    DISALLOW_COPY_AND_ASSIGN(Delegate);
  };

  // Registers |delegate| on the current thread. Must be called once and only
  // once per thread before using RunLoop methods on it. |delegate| is from then
  // on forever bound to that thread (including its destruction). The returned
  // Delegate::Client is valid as long as |delegate| is kept alive.
  static Delegate::Client* RegisterDelegateForCurrentThread(Delegate* delegate);

 private:
  // TODO(gab): Break the inter-dependency between MessageLoop and RunLoop
  // further. http://crbug.com/703346
  friend class MessageLoop;
#if defined(OS_ANDROID)
  // Android doesn't support the blocking MessageLoop::Run, so it calls
  // BeforeRun and AfterRun directly.
  friend class base::MessagePumpForUI;
#endif

#if defined(OS_IOS)
  // iOS doesn't support the blocking MessageLoop::Run, so it calls
  // BeforeRun directly.
  friend class base::MessagePumpUIApplication;
#endif

  // Return false to abort the Run.
  bool BeforeRun();
  void AfterRun();

  // A copy of RunLoop::Delegate for the thread driven by tis RunLoop for quick
  // access without using TLS (also allows access to state from another sequence
  // during Run(), ref. |sequence_checker_| below).
  Delegate* delegate_;

#if DCHECK_IS_ON()
  bool run_called_ = false;
#endif

  bool quit_called_ = false;
  bool running_ = false;
  // Used to record that QuitWhenIdle() was called on the MessageLoop, meaning
  // that we should quit Run once it becomes idle.
  bool quit_when_idle_received_ = false;

  // RunLoop is not thread-safe. Its state/methods, unless marked as such, may
  // not be accessed from any other sequence than the thread it was constructed
  // on. Exception: RunLoop can be safely accessed from one other sequence (or
  // single parallel task) during Run() -- e.g. to Quit() without having to
  // plumb ThreatTaskRunnerHandle::Get() throughout a test to repost QuitClosure
  // to origin thread.
  SEQUENCE_CHECKER(sequence_checker_);

  const scoped_refptr<SingleThreadTaskRunner> origin_task_runner_;

  // WeakPtrFactory for QuitClosure safety.
  base::WeakPtrFactory<RunLoop> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RunLoop);
};

}  // namespace base

#endif  // BASE_RUN_LOOP_H_
