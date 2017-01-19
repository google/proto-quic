// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/disk_cache_test_base.h"

#include <utility>

#include "base/files/file_util.h"
#include "base/path_service.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/cache_util.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/disk_cache/memory/mem_backend_impl.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_index.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsOk;

DiskCacheTest::DiskCacheTest() {
  CHECK(temp_dir_.CreateUniqueTempDir());
  cache_path_ = temp_dir_.GetPath();
  if (!base::MessageLoop::current())
    message_loop_.reset(new base::MessageLoopForIO());
}

DiskCacheTest::~DiskCacheTest() {
}

bool DiskCacheTest::CopyTestCache(const std::string& name) {
  base::FilePath path;
  PathService::Get(base::DIR_SOURCE_ROOT, &path);
  path = path.AppendASCII("net");
  path = path.AppendASCII("data");
  path = path.AppendASCII("cache_tests");
  path = path.AppendASCII(name);

  if (!CleanupCacheDir())
    return false;
  return base::CopyDirectory(path, cache_path_, false);
}

bool DiskCacheTest::CleanupCacheDir() {
  return DeleteCache(cache_path_);
}

void DiskCacheTest::TearDown() {
  base::RunLoop().RunUntilIdle();
}

DiskCacheTestWithCache::TestIterator::TestIterator(
    std::unique_ptr<disk_cache::Backend::Iterator> iterator)
    : iterator_(std::move(iterator)) {}

DiskCacheTestWithCache::TestIterator::~TestIterator() {}

int DiskCacheTestWithCache::TestIterator::OpenNextEntry(
    disk_cache::Entry** next_entry) {
  net::TestCompletionCallback cb;
  int rv = iterator_->OpenNextEntry(next_entry, cb.callback());
  return cb.GetResult(rv);
}

DiskCacheTestWithCache::DiskCacheTestWithCache()
    : cache_impl_(NULL),
      simple_cache_impl_(NULL),
      mem_cache_(NULL),
      mask_(0),
      size_(0),
      type_(net::DISK_CACHE),
      memory_only_(false),
      simple_cache_mode_(false),
      simple_cache_wait_for_index_(true),
      force_creation_(false),
      new_eviction_(false),
      first_cleanup_(true),
      integrity_(true),
      use_current_thread_(false),
      cache_thread_("CacheThread") {
}

DiskCacheTestWithCache::~DiskCacheTestWithCache() {}

void DiskCacheTestWithCache::InitCache() {
  if (memory_only_)
    InitMemoryCache();
  else
    InitDiskCache();

  ASSERT_TRUE(NULL != cache_);
  if (first_cleanup_)
    ASSERT_EQ(0, cache_->GetEntryCount());
}

// We are expected to leak memory when simulating crashes.
void DiskCacheTestWithCache::SimulateCrash() {
  ASSERT_TRUE(!memory_only_);
  net::TestCompletionCallback cb;
  int rv = cache_impl_->FlushQueueForTest(cb.callback());
  ASSERT_THAT(cb.GetResult(rv), IsOk());
  cache_impl_->ClearRefCountForTest();

  cache_.reset();
  EXPECT_TRUE(CheckCacheIntegrity(cache_path_, new_eviction_, mask_));

  CreateBackend(disk_cache::kNoRandom, &cache_thread_);
}

void DiskCacheTestWithCache::SetTestMode() {
  ASSERT_TRUE(!memory_only_);
  cache_impl_->SetUnitTestMode();
}

void DiskCacheTestWithCache::SetMaxSize(int size) {
  size_ = size;
  if (simple_cache_impl_)
    EXPECT_TRUE(simple_cache_impl_->SetMaxSize(size));

  if (cache_impl_)
    EXPECT_TRUE(cache_impl_->SetMaxSize(size));

  if (mem_cache_)
    EXPECT_TRUE(mem_cache_->SetMaxSize(size));
}

int DiskCacheTestWithCache::OpenEntry(const std::string& key,
                                      disk_cache::Entry** entry) {
  net::TestCompletionCallback cb;
  int rv = cache_->OpenEntry(key, entry, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::CreateEntry(const std::string& key,
                                        disk_cache::Entry** entry) {
  net::TestCompletionCallback cb;
  int rv = cache_->CreateEntry(key, entry, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::DoomEntry(const std::string& key) {
  net::TestCompletionCallback cb;
  int rv = cache_->DoomEntry(key, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::DoomAllEntries() {
  net::TestCompletionCallback cb;
  int rv = cache_->DoomAllEntries(cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::DoomEntriesBetween(const base::Time initial_time,
                                               const base::Time end_time) {
  net::TestCompletionCallback cb;
  int rv = cache_->DoomEntriesBetween(initial_time, end_time, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::DoomEntriesSince(const base::Time initial_time) {
  net::TestCompletionCallback cb;
  int rv = cache_->DoomEntriesSince(initial_time, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::CalculateSizeOfAllEntries() {
  net::TestCompletionCallback cb;
  int rv = cache_->CalculateSizeOfAllEntries(cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::CalculateSizeOfEntriesBetween(
    const base::Time initial_time,
    const base::Time end_time) {
  net::TestCompletionCallback cb;
  int rv = cache_->CalculateSizeOfEntriesBetween(initial_time, end_time,
                                                 cb.callback());
  return cb.GetResult(rv);
}

std::unique_ptr<DiskCacheTestWithCache::TestIterator>
DiskCacheTestWithCache::CreateIterator() {
  return std::unique_ptr<TestIterator>(
      new TestIterator(cache_->CreateIterator()));
}

void DiskCacheTestWithCache::FlushQueueForTest() {
  if (memory_only_ || !cache_impl_)
    return;

  net::TestCompletionCallback cb;
  int rv = cache_impl_->FlushQueueForTest(cb.callback());
  EXPECT_THAT(cb.GetResult(rv), IsOk());
}

void DiskCacheTestWithCache::RunTaskForTest(const base::Closure& closure) {
  if (memory_only_ || !cache_impl_) {
    closure.Run();
    return;
  }

  net::TestCompletionCallback cb;
  int rv = cache_impl_->RunTaskForTest(closure, cb.callback());
  EXPECT_THAT(cb.GetResult(rv), IsOk());
}

int DiskCacheTestWithCache::ReadData(disk_cache::Entry* entry, int index,
                                     int offset, net::IOBuffer* buf, int len) {
  net::TestCompletionCallback cb;
  int rv = entry->ReadData(index, offset, buf, len, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::WriteData(disk_cache::Entry* entry, int index,
                                      int offset, net::IOBuffer* buf, int len,
                                      bool truncate) {
  net::TestCompletionCallback cb;
  int rv = entry->WriteData(index, offset, buf, len, cb.callback(), truncate);
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::ReadSparseData(disk_cache::Entry* entry,
                                           int64_t offset,
                                           net::IOBuffer* buf,
                                           int len) {
  net::TestCompletionCallback cb;
  int rv = entry->ReadSparseData(offset, buf, len, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::WriteSparseData(disk_cache::Entry* entry,
                                            int64_t offset,
                                            net::IOBuffer* buf,
                                            int len) {
  net::TestCompletionCallback cb;
  int rv = entry->WriteSparseData(offset, buf, len, cb.callback());
  return cb.GetResult(rv);
}

void DiskCacheTestWithCache::TrimForTest(bool empty) {
  RunTaskForTest(base::Bind(&disk_cache::BackendImpl::TrimForTest,
                            base::Unretained(cache_impl_),
                            empty));
}

void DiskCacheTestWithCache::TrimDeletedListForTest(bool empty) {
  RunTaskForTest(base::Bind(&disk_cache::BackendImpl::TrimDeletedListForTest,
                            base::Unretained(cache_impl_),
                            empty));
}

void DiskCacheTestWithCache::AddDelay() {
  if (simple_cache_mode_) {
    // The simple cache uses second resolution for many timeouts, so it's safest
    // to advance by at least whole seconds before falling back into the normal
    // disk cache epsilon advance.
    const base::Time initial_time = base::Time::Now();
    do {
      base::PlatformThread::YieldCurrentThread();
    } while (base::Time::Now() -
             initial_time < base::TimeDelta::FromSeconds(1));
  }

  base::Time initial = base::Time::Now();
  while (base::Time::Now() <= initial) {
    base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(1));
  };
}

void DiskCacheTestWithCache::TearDown() {
  base::RunLoop().RunUntilIdle();
  disk_cache::SimpleBackendImpl::FlushWorkerPoolForTesting();
  base::RunLoop().RunUntilIdle();
  cache_.reset();
  if (cache_thread_.IsRunning())
    cache_thread_.Stop();

  if (!memory_only_ && !simple_cache_mode_ && integrity_) {
    EXPECT_TRUE(CheckCacheIntegrity(cache_path_, new_eviction_, mask_));
  }
  base::RunLoop().RunUntilIdle();
  disk_cache::SimpleBackendImpl::FlushWorkerPoolForTesting();
  DiskCacheTest::TearDown();
}

void DiskCacheTestWithCache::InitMemoryCache() {
  mem_cache_ = new disk_cache::MemBackendImpl(NULL);
  cache_.reset(mem_cache_);
  ASSERT_TRUE(cache_);

  if (size_)
    EXPECT_TRUE(mem_cache_->SetMaxSize(size_));

  ASSERT_TRUE(mem_cache_->Init());
}

void DiskCacheTestWithCache::InitDiskCache() {
  if (first_cleanup_)
    ASSERT_TRUE(CleanupCacheDir());

  if (!cache_thread_.IsRunning()) {
    ASSERT_TRUE(cache_thread_.StartWithOptions(
        base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));
  }
  ASSERT_TRUE(cache_thread_.message_loop() != NULL);

  CreateBackend(disk_cache::kNoRandom, &cache_thread_);
}

void DiskCacheTestWithCache::CreateBackend(uint32_t flags,
                                           base::Thread* thread) {
  scoped_refptr<base::SingleThreadTaskRunner> runner;
  if (use_current_thread_)
    runner = base::ThreadTaskRunnerHandle::Get();
  else
    runner = thread->task_runner();

  if (simple_cache_mode_) {
    net::TestCompletionCallback cb;
    std::unique_ptr<disk_cache::SimpleBackendImpl> simple_backend(
        new disk_cache::SimpleBackendImpl(cache_path_, size_, type_, runner,
                                          NULL));
    int rv = simple_backend->Init(cb.callback());
    ASSERT_THAT(cb.GetResult(rv), IsOk());
    simple_cache_impl_ = simple_backend.get();
    cache_ = std::move(simple_backend);
    if (simple_cache_wait_for_index_) {
      net::TestCompletionCallback wait_for_index_cb;
      rv = simple_cache_impl_->index()->ExecuteWhenReady(
          wait_for_index_cb.callback());
      ASSERT_THAT(wait_for_index_cb.GetResult(rv), IsOk());
    }
    return;
  }

  if (mask_)
    cache_impl_ = new disk_cache::BackendImpl(cache_path_, mask_, runner, NULL);
  else
    cache_impl_ = new disk_cache::BackendImpl(cache_path_, runner, NULL);
  cache_.reset(cache_impl_);
  ASSERT_TRUE(cache_);
  if (size_)
    EXPECT_TRUE(cache_impl_->SetMaxSize(size_));
  if (new_eviction_)
    cache_impl_->SetNewEviction();
  cache_impl_->SetType(type_);
  cache_impl_->SetFlags(flags);
  net::TestCompletionCallback cb;
  int rv = cache_impl_->Init(cb.callback());
  ASSERT_THAT(cb.GetResult(rv), IsOk());
}
