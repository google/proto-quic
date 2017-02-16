// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_RUNNER_UTIL_H_
#define BASE_TASK_RUNNER_UTIL_H_

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/post_task_and_reply_with_result_internal.h"
#include "base/task_runner.h"

namespace base {

// When you have these methods
//
//   R DoWorkAndReturn();
//   void Callback(const R& result);
//
// and want to call them in a PostTaskAndReply kind of fashion where the
// result of DoWorkAndReturn is passed to the Callback, you can use
// PostTaskAndReplyWithResult as in this example:
//
// PostTaskAndReplyWithResult(
//     target_thread_.task_runner(),
//     FROM_HERE,
//     Bind(&DoWorkAndReturn),
//     Bind(&Callback));
template <typename TaskReturnType, typename ReplyArgType>
bool PostTaskAndReplyWithResult(TaskRunner* task_runner,
                                const tracked_objects::Location& from_here,
                                Callback<TaskReturnType()> task,
                                Callback<void(ReplyArgType)> reply) {
  DCHECK(task);
  DCHECK(reply);
  TaskReturnType* result = new TaskReturnType();
  return task_runner->PostTaskAndReply(
      from_here, base::Bind(&internal::ReturnAsParamAdapter<TaskReturnType>,
                            std::move(task), result),
      base::Bind(&internal::ReplyAdapter<TaskReturnType, ReplyArgType>,
                 std::move(reply), base::Owned(result)));
}

}  // namespace base

#endif  // BASE_TASK_RUNNER_UTIL_H_
