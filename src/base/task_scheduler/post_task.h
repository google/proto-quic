// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_POST_TASK_H_
#define BASE_TASK_SCHEDULER_POST_TASK_H_

#include "base/base_export.h"
#include "base/bind.h"
#include "base/callback_forward.h"
#include "base/location.h"
#include "base/memory/ref_counted.h"
#include "base/post_task_and_reply_with_result_internal.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner.h"
#include "base/task_scheduler/task_traits.h"

namespace base {

// This is the preferred interface to post tasks to the TaskScheduler.
//
// Note: The TaskScheduler is still in an experimental phase in Chrome. Please
// refrain from using this API unless you know what you are doing.
//
// TaskScheduler must have been registered for the current process via
// TaskScheduler::SetInstance() before the functions below are valid.
//
// To post a simple one-off task:
//     PostTask(FROM_HERE, Bind(...));
//
// To post a high priority one-off task to respond to a user interaction:
//     PostTaskWithTraits(
//         FROM_HERE,
//         TaskTraits().WithPriority(TaskPriority::USER_BLOCKING),
//         Bind(...));
//
// To post tasks that must run in sequence:
//     scoped_refptr<SequencedTaskRunner> task_runner =
//         CreateSequencedTaskRunnerWithTraits(TaskTraits());
//     task_runner.PostTask(FROM_HERE, Bind(...));
//     task_runner.PostTask(FROM_HERE, Bind(...));
//
// To post file I/O tasks that must run in sequence and can be skipped on
// shutdown:
//     scoped_refptr<SequencedTaskRunner> task_runner =
//         CreateSequencedTaskRunnerWithTraits(
//             TaskTraits().WithFileIO().WithShutdownBehavior(
//                 TaskShutdownBehavior::SKIP_ON_SHUTDOWN));
//     task_runner.PostTask(FROM_HERE, Bind(...));
//     task_runner.PostTask(FROM_HERE, Bind(...));
//
// The default TaskTraits apply to tasks that:
//     (1) don't need to do I/O,
//     (2) don't affect user interaction and/or visible elements, and
//     (3) can either block shutdown or be skipped on shutdown
//         (barring current TaskScheduler default).
// If those loose requirements are sufficient for your task, use
// PostTask[AndReply], otherwise override these with explicit traits via
// PostTaskWithTraits[AndReply].

// Posts |task| to the TaskScheduler. Calling this is equivalent to calling
// PostTaskWithTraits with plain TaskTraits.
BASE_EXPORT void PostTask(const tracked_objects::Location& from_here,
                          const Closure& task);

// Posts |task| to the TaskScheduler and posts |reply| on the caller's execution
// context (i.e. same sequence or thread and same TaskTraits if applicable) when
// |task| completes. Calling this is equivalent to calling
// PostTaskWithTraitsAndReply with plain TaskTraits. Can only be called when
// SequencedTaskRunnerHandle::IsSet().
BASE_EXPORT void PostTaskAndReply(const tracked_objects::Location& from_here,
                                  const Closure& task,
                                  const Closure& reply);

// Posts |task| to the TaskScheduler and posts |reply| with the return value of
// |task| as argument on the caller's execution context (i.e. same sequence or
// thread and same TaskTraits if applicable) when |task| completes. Calling this
// is equivalent to calling PostTaskWithTraitsAndReplyWithResult with plain
// TaskTraits. Can only be called when SequencedTaskRunnerHandle::IsSet().
template <typename TaskReturnType, typename ReplyArgType>
void PostTaskAndReplyWithResult(const tracked_objects::Location& from_here,
                                const Callback<TaskReturnType(void)>& task,
                                const Callback<void(ReplyArgType)>& reply) {
  PostTaskWithTraitsAndReplyWithResult(from_here, TaskTraits(), task, reply);
}

// Posts |task| with specific |traits| to the TaskScheduler.
BASE_EXPORT void PostTaskWithTraits(const tracked_objects::Location& from_here,
                                    const TaskTraits& traits,
                                    const Closure& task);

// Posts |task| with specific |traits| to the TaskScheduler and posts |reply| on
// the caller's execution context (i.e. same sequence or thread and same
// TaskTraits if applicable) when |task| completes. Can only be called when
// SequencedTaskRunnerHandle::IsSet().
BASE_EXPORT void PostTaskWithTraitsAndReply(
    const tracked_objects::Location& from_here,
    const TaskTraits& traits,
    const Closure& task,
    const Closure& reply);

// Posts |task| with specific |traits| to the TaskScheduler and posts |reply|
// with the return value of |task| as argument on the caller's execution context
// (i.e. same sequence or thread and same TaskTraits if applicable) when |task|
// completes. Can only be called when SequencedTaskRunnerHandle::IsSet().
template <typename TaskReturnType, typename ReplyArgType>
void PostTaskWithTraitsAndReplyWithResult(
    const tracked_objects::Location& from_here,
    const TaskTraits& traits,
    const Callback<TaskReturnType(void)>& task,
    const Callback<void(ReplyArgType)>& reply) {
  TaskReturnType* result = new TaskReturnType();
  return PostTaskWithTraitsAndReply(
      from_here, traits,
      Bind(&internal::ReturnAsParamAdapter<TaskReturnType>, task, result),
      Bind(&internal::ReplyAdapter<TaskReturnType, ReplyArgType>, reply,
           Owned(result)));
}

// Delayed tasks posted to TaskRunners returned by the functions below may be
// coalesced (i.e. delays may be adjusted to reduce the number of wakeups and
// hence power consumption).

// Returns a TaskRunner whose PostTask invocations result in scheduling tasks
// using |traits|. Tasks may run in any order and in parallel.
BASE_EXPORT scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
    const TaskTraits& traits);

// Returns a SequencedTaskRunner whose PostTask invocations result in scheduling
// tasks using |traits|. Tasks run one at a time in posting order.
BASE_EXPORT scoped_refptr<SequencedTaskRunner>
CreateSequencedTaskRunnerWithTraits(const TaskTraits& traits);

// Returns a SingleThreadTaskRunner whose PostTask invocations result in
// scheduling tasks using |traits|. Tasks run on a single thread in posting
// order.
//
// If all you need is to make sure that tasks don't run concurrently (e.g.
// because they access a data structure which is not thread-safe), use
// CreateSequencedTaskRunnerWithTraits(). Only use this if you rely on a thread-
// affine API (it might be safer to assume thread-affinity when dealing with
// under-documented third-party APIs, e.g. other OS') or share data across tasks
// using thread-local storage.
BASE_EXPORT scoped_refptr<SingleThreadTaskRunner>
CreateSingleThreadTaskRunnerWithTraits(const TaskTraits& traits);

}  // namespace base

#endif  // BASE_TASK_SCHEDULER_POST_TASK_H_
