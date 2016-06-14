// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/synchronization/condition_variable.h"

#include "base/synchronization/lock.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"

namespace base {

ConditionVariable::ConditionVariable(Lock* user_lock)
    : srwlock_(user_lock->lock_.native_handle())
#if DCHECK_IS_ON()
    , user_lock_(user_lock)
#endif
{
  DCHECK(user_lock);
  InitializeConditionVariable(&cv_);
}

ConditionVariable::~ConditionVariable() = default;

void ConditionVariable::Wait() {
  TimedWait(TimeDelta::FromMilliseconds(INFINITE));
}

void ConditionVariable::TimedWait(const TimeDelta& max_time) {
  base::ThreadRestrictions::AssertWaitAllowed();
  DWORD timeout = static_cast<DWORD>(max_time.InMilliseconds());

#if DCHECK_IS_ON()
  user_lock_->CheckHeldAndUnmark();
#endif

  if (!SleepConditionVariableSRW(&cv_, srwlock_, timeout, 0)) {
    DCHECK_EQ(static_cast<DWORD>(ERROR_TIMEOUT), GetLastError());
  }

#if DCHECK_IS_ON()
  user_lock_->CheckUnheldAndMark();
#endif
}

void ConditionVariable::Broadcast() {
  WakeAllConditionVariable(&cv_);
}

void ConditionVariable::Signal() {
  WakeConditionVariable(&cv_);
}

}  // namespace base
