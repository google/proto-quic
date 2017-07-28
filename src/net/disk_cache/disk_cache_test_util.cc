// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/disk_cache_test_util.h"

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/file.h"
#include "net/disk_cache/cache_util.h"

using base::Time;
using base::TimeDelta;

std::string GenerateKey(bool same_length) {
  char key[200];
  CacheTestFillBuffer(key, sizeof(key), same_length);

  key[199] = '\0';
  return std::string(key);
}

void CacheTestFillBuffer(char* buffer, size_t len, bool no_nulls) {
  static bool called = false;
  if (!called) {
    called = true;
    int seed = static_cast<int>(Time::Now().ToInternalValue());
    srand(seed);
  }

  for (size_t i = 0; i < len; i++) {
    buffer[i] = static_cast<char>(rand());
    if (!buffer[i] && no_nulls)
      buffer[i] = 'g';
  }
  if (len && !buffer[0])
    buffer[0] = 'g';
}

bool CreateCacheTestFile(const base::FilePath& name) {
  int flags = base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_READ |
              base::File::FLAG_WRITE;

  base::File file(name, flags);
  if (!file.IsValid())
    return false;

  file.SetLength(4 * 1024 * 1024);
  return true;
}

bool DeleteCache(const base::FilePath& path) {
  disk_cache::DeleteCache(path, false);
  return true;
}

bool CheckCacheIntegrity(const base::FilePath& path,
                         bool new_eviction,
                         uint32_t mask) {
  std::unique_ptr<disk_cache::BackendImpl> cache(new disk_cache::BackendImpl(
      path, mask, base::ThreadTaskRunnerHandle::Get(), NULL));
  if (!cache.get())
    return false;
  if (new_eviction)
    cache->SetNewEviction();
  cache->SetFlags(disk_cache::kNoRandom);
  if (cache->SyncInit() != net::OK)
    return false;
  return cache->SelfCheck() >= 0;
}

// -----------------------------------------------------------------------

MessageLoopHelper::MessageLoopHelper()
    : num_callbacks_(0),
      num_iterations_(0),
      last_(0),
      completed_(false),
      callback_reused_error_(false),
      callbacks_called_(0) {
}

MessageLoopHelper::~MessageLoopHelper() {
}

bool MessageLoopHelper::WaitUntilCacheIoFinished(int num_callbacks) {
  if (num_callbacks == callbacks_called_)
    return true;

  ExpectCallbacks(num_callbacks);
  // Create a recurrent timer of 50 mS.
  if (!timer_.IsRunning())
    timer_.Start(FROM_HERE, TimeDelta::FromMilliseconds(50), this,
                 &MessageLoopHelper::TimerExpired);
  base::RunLoop().Run();
  return completed_;
}

// Quits the message loop when all callbacks are called or we've been waiting
// too long for them (2 secs without a callback).
void MessageLoopHelper::TimerExpired() {
  CHECK_LE(callbacks_called_, num_callbacks_);
  if (callbacks_called_ == num_callbacks_) {
    completed_ = true;
    base::RunLoop::QuitCurrentWhenIdleDeprecated();
  } else {
    // Not finished yet. See if we have to abort.
    if (last_ == callbacks_called_)
      num_iterations_++;
    else
      last_ = callbacks_called_;
    if (40 == num_iterations_)
      base::RunLoop::QuitCurrentWhenIdleDeprecated();
  }
}

// -----------------------------------------------------------------------

CallbackTest::CallbackTest(MessageLoopHelper* helper,
                           bool reuse)
    : helper_(helper),
      reuse_(reuse ? 0 : 1) {
}

CallbackTest::~CallbackTest() {
}

// On the actual callback, increase the number of tests received and check for
// errors (an unexpected test received)
void CallbackTest::Run(int result) {
  last_result_ = result;

  if (reuse_) {
    DCHECK_EQ(1, reuse_);
    if (2 == reuse_)
      helper_->set_callback_reused_error(true);
    reuse_++;
  }

  helper_->CallbackWasCalled();
}
