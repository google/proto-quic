// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/post_task.h"

#include "base/task_scheduler/task_scheduler.h"
#include "base/threading/post_task_and_reply_impl.h"

namespace base {

namespace {

class PostTaskAndReplyTaskRunner : public internal::PostTaskAndReplyImpl {
 public:
  explicit PostTaskAndReplyTaskRunner(const TaskTraits& traits)
      : traits_(traits) {}

 private:
  bool PostTask(const tracked_objects::Location& from_here,
                const Closure& task) override {
    PostTaskWithTraits(from_here, traits_, task);
    return true;
  }

  const TaskTraits traits_;
};


}  // namespace

void PostTask(const tracked_objects::Location& from_here, const Closure& task) {
  PostDelayedTask(from_here, task, TimeDelta());
}

void PostDelayedTask(const tracked_objects::Location& from_here,
                     const Closure& task,
                     TimeDelta delay) {
  PostDelayedTaskWithTraits(from_here, TaskTraits(), task, delay);
}

void PostTaskAndReply(const tracked_objects::Location& from_here,
                      const Closure& task,
                      const Closure& reply) {
  PostTaskWithTraitsAndReply(from_here, TaskTraits(), task, reply);
}

void PostTaskWithTraits(const tracked_objects::Location& from_here,
                        const TaskTraits& traits,
                        const Closure& task) {
  PostDelayedTaskWithTraits(from_here, traits, task, TimeDelta());
}

void PostDelayedTaskWithTraits(const tracked_objects::Location& from_here,
                               const TaskTraits& traits,
                               const Closure& task,
                               TimeDelta delay) {
  TaskScheduler::GetInstance()->PostDelayedTaskWithTraits(from_here, traits,
                                                          task, delay);
}

void PostTaskWithTraitsAndReply(const tracked_objects::Location& from_here,
                                const TaskTraits& traits,
                                const Closure& task,
                                const Closure& reply) {
  PostTaskAndReplyTaskRunner(traits).PostTaskAndReply(from_here, task, reply);
}

scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(const TaskTraits& traits) {
  return TaskScheduler::GetInstance()->CreateTaskRunnerWithTraits(traits);
}

scoped_refptr<SequencedTaskRunner> CreateSequencedTaskRunnerWithTraits(
    const TaskTraits& traits) {
  return TaskScheduler::GetInstance()->CreateSequencedTaskRunnerWithTraits(
      traits);
}

scoped_refptr<SingleThreadTaskRunner> CreateSingleThreadTaskRunnerWithTraits(
    const TaskTraits& traits) {
  return TaskScheduler::GetInstance()->CreateSingleThreadTaskRunnerWithTraits(
      traits);
}

}  // namespace base
