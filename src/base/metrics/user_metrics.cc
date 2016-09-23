// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/user_metrics.h"

#include <stddef.h>

#include <vector>

#include "base/bind.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/threading/thread_checker.h"

namespace base {
namespace {

LazyInstance<std::vector<ActionCallback>> g_callbacks =
    LAZY_INSTANCE_INITIALIZER;
LazyInstance<scoped_refptr<SingleThreadTaskRunner>> g_task_runner =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

void RecordAction(const UserMetricsAction& action) {
  RecordComputedAction(action.str_);
}

void RecordComputedAction(const std::string& action) {
  if (!g_task_runner.Get()) {
    DCHECK(g_callbacks.Get().empty());
    return;
  }

  if (!g_task_runner.Get()->BelongsToCurrentThread()) {
    g_task_runner.Get()->PostTask(FROM_HERE,
                                  Bind(&RecordComputedAction, action));
    return;
  }

  for (const ActionCallback& callback : g_callbacks.Get()) {
    callback.Run(action);
  }
}

void AddActionCallback(const ActionCallback& callback) {
  // Only allow adding a callback if the task runner is set.
  DCHECK(g_task_runner.Get());
  DCHECK(g_task_runner.Get()->BelongsToCurrentThread());
  g_callbacks.Get().push_back(callback);
}

void RemoveActionCallback(const ActionCallback& callback) {
  DCHECK(g_task_runner.Get());
  DCHECK(g_task_runner.Get()->BelongsToCurrentThread());
  std::vector<ActionCallback>* callbacks = g_callbacks.Pointer();
  for (size_t i = 0; i < callbacks->size(); ++i) {
    if ((*callbacks)[i].Equals(callback)) {
      callbacks->erase(callbacks->begin() + i);
      return;
    }
  }
}

void SetRecordActionTaskRunner(
    scoped_refptr<SingleThreadTaskRunner> task_runner) {
  DCHECK(task_runner->BelongsToCurrentThread());
  DCHECK(!g_task_runner.Get() || g_task_runner.Get()->BelongsToCurrentThread());
  g_task_runner.Get() = task_runner;
}

}  // namespace base
