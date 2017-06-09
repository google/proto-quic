// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/test_utils.h"

#include <utility>

namespace base {
namespace internal {
namespace test {

scoped_refptr<Sequence> CreateSequenceWithTask(std::unique_ptr<Task> task) {
  scoped_refptr<Sequence> sequence = MakeRefCounted<Sequence>();
  sequence->PushTask(std::move(task));
  return sequence;
}

}  // namespace test
}  // namespace internal
}  // namespace base
