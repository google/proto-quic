// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <string>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_path.h"
#include "base/hash.h"
#include "base/process/process_metrics.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/test/perf_time_logger.h"
#include "base/test/test_file_util.h"
#include "base/threading/thread.h"
#include "net/base/cache_type.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/block_files.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/disk_cache_test_base.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using base::Time;

namespace {

size_t MaybeGetMaxFds() {
#if defined(OS_POSIX)
  return base::GetMaxFds();
#else
  return std::numeric_limits<size_t>::max();
#endif
}

void MaybeSetFdLimit(unsigned int max_descriptors) {
#if defined(OS_POSIX)
  base::SetFdLimit(max_descriptors);
#endif
}

struct TestEntry {
  std::string key;
  int data_len;
};

class DiskCachePerfTest : public DiskCacheTestWithCache {
 public:
  DiskCachePerfTest() : saved_fd_limit_(MaybeGetMaxFds()) {
    if (saved_fd_limit_ < kFdLimitForCacheTests)
      MaybeSetFdLimit(kFdLimitForCacheTests);
  }

  ~DiskCachePerfTest() override {
    if (saved_fd_limit_ < kFdLimitForCacheTests)
      MaybeSetFdLimit(kFdLimitForCacheTests);
  }

 protected:
  enum class WhatToRead {
    HEADERS_ONLY,
    HEADERS_AND_BODY,
  };

  // Helper methods for constructing tests.
  bool TimeWrite();
  bool TimeRead(WhatToRead what_to_read, const char* timer_message);
  void ResetAndEvictSystemDiskCache();

  // Complete perf tests.
  void CacheBackendPerformance();

  const size_t kFdLimitForCacheTests = 8192;

  const int kNumEntries = 1000;
  const int kHeadersSize = 800;
  const int kBodySize = 256 * 1024 - 1;

  std::vector<TestEntry> entries_;

 private:
  const size_t saved_fd_limit_;
};

// Creates num_entries on the cache, and writes kHeaderSize bytes of metadata
// and up to kBodySize of data to each entry.
bool DiskCachePerfTest::TimeWrite() {
  // TODO(gavinp): This test would be significantly more realistic if it didn't
  // do single reads and writes. Perhaps entries should be written 64kb at a
  // time. As well, not all entries should be created and written essentially
  // simultaneously; some number of entries in flight at a time would be a
  // likely better testing load.
  scoped_refptr<net::IOBuffer> buffer1(new net::IOBuffer(kHeadersSize));
  scoped_refptr<net::IOBuffer> buffer2(new net::IOBuffer(kBodySize));

  CacheTestFillBuffer(buffer1->data(), kHeadersSize, false);
  CacheTestFillBuffer(buffer2->data(), kBodySize, false);

  int expected = 0;

  MessageLoopHelper helper;
  CallbackTest callback(&helper, true);

  base::PerfTimeLogger timer("Write disk cache entries");

  for (int i = 0; i < kNumEntries; i++) {
    TestEntry entry;
    entry.key = GenerateKey(true);
    entry.data_len = rand() % kBodySize;
    entries_.push_back(entry);

    disk_cache::Entry* cache_entry;
    net::TestCompletionCallback cb;
    int rv = cache_->CreateEntry(entry.key, &cache_entry, cb.callback());
    if (net::OK != cb.GetResult(rv))
      break;
    int ret = cache_entry->WriteData(
        0, 0, buffer1.get(), kHeadersSize,
        base::Bind(&CallbackTest::Run, base::Unretained(&callback)), false);
    if (net::ERR_IO_PENDING == ret)
      expected++;
    else if (kHeadersSize != ret)
      break;

    ret = cache_entry->WriteData(
        1, 0, buffer2.get(), entry.data_len,
        base::Bind(&CallbackTest::Run, base::Unretained(&callback)), false);
    if (net::ERR_IO_PENDING == ret)
      expected++;
    else if (entry.data_len != ret)
      break;
    cache_entry->Close();
  }

  helper.WaitUntilCacheIoFinished(expected);
  timer.Done();

  return expected == helper.callbacks_called();
}

// Reads the data and metadata from each entry listed on |entries|.
bool DiskCachePerfTest::TimeRead(WhatToRead what_to_read,
                                 const char* timer_message) {
  scoped_refptr<net::IOBuffer> buffer1(new net::IOBuffer(kHeadersSize));
  scoped_refptr<net::IOBuffer> buffer2(new net::IOBuffer(kBodySize));

  CacheTestFillBuffer(buffer1->data(), kHeadersSize, false);
  CacheTestFillBuffer(buffer2->data(), kBodySize, false);

  int expected = 0;

  MessageLoopHelper helper;
  CallbackTest callback(&helper, true);

  base::PerfTimeLogger timer(timer_message);

  for (int i = 0; i < kNumEntries; i++) {
    disk_cache::Entry* cache_entry;
    net::TestCompletionCallback cb;
    int rv = cache_->OpenEntry(entries_[i].key, &cache_entry, cb.callback());
    if (net::OK != cb.GetResult(rv))
      break;
    int ret = cache_entry->ReadData(
        0, 0, buffer1.get(), kHeadersSize,
        base::Bind(&CallbackTest::Run, base::Unretained(&callback)));
    if (net::ERR_IO_PENDING == ret)
      expected++;
    else if (kHeadersSize != ret)
      break;

    if (what_to_read == WhatToRead::HEADERS_AND_BODY) {
      ret = cache_entry->ReadData(
          1, 0, buffer2.get(), entries_[i].data_len,
          base::Bind(&CallbackTest::Run, base::Unretained(&callback)));
      if (net::ERR_IO_PENDING == ret)
        expected++;
      else if (entries_[i].data_len != ret)
        break;
    }

    cache_entry->Close();
  }

  helper.WaitUntilCacheIoFinished(expected);
  timer.Done();

  return (expected == helper.callbacks_called());
}

TEST_F(DiskCachePerfTest, BlockfileHashes) {
  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);

  base::PerfTimeLogger timer("Hash disk cache keys");
  for (int i = 0; i < 300000; i++) {
    std::string key = GenerateKey(true);
    base::Hash(key);
  }
  timer.Done();
}

void DiskCachePerfTest::ResetAndEvictSystemDiskCache() {
  base::RunLoop().RunUntilIdle();
  cache_.reset();

  // Flush all files in the cache out of system memory.
  const base::FilePath::StringType file_pattern = FILE_PATH_LITERAL("*");
  base::FileEnumerator enumerator(cache_path_, true /* recursive */,
                                  base::FileEnumerator::FILES, file_pattern);
  for (base::FilePath file_path = enumerator.Next(); !file_path.empty();
       file_path = enumerator.Next()) {
    ASSERT_TRUE(base::EvictFileFromSystemCache(file_path));
  }
#if defined(OS_LINUX)
  // And, cache directories, on platforms where the eviction utility supports
  // this (currently Linux only).
  if (simple_cache_mode_) {
    ASSERT_TRUE(
        base::EvictFileFromSystemCache(cache_path_.AppendASCII("index-dir")));
  }
  ASSERT_TRUE(base::EvictFileFromSystemCache(cache_path_));
#endif

  DisableFirstCleanup();
  InitCache();
}

void DiskCachePerfTest::CacheBackendPerformance() {
  InitCache();
  EXPECT_TRUE(TimeWrite());

  disk_cache::SimpleBackendImpl::FlushWorkerPoolForTesting();
  base::RunLoop().RunUntilIdle();

  ResetAndEvictSystemDiskCache();
  EXPECT_TRUE(TimeRead(WhatToRead::HEADERS_ONLY,
                       "Read disk cache headers only (cold)"));
  EXPECT_TRUE(TimeRead(WhatToRead::HEADERS_ONLY,
                       "Read disk cache headers only (warm)"));

  disk_cache::SimpleBackendImpl::FlushWorkerPoolForTesting();
  base::RunLoop().RunUntilIdle();

  ResetAndEvictSystemDiskCache();
  EXPECT_TRUE(
      TimeRead(WhatToRead::HEADERS_AND_BODY, "Read disk cache entries (cold)"));
  EXPECT_TRUE(
      TimeRead(WhatToRead::HEADERS_AND_BODY, "Read disk cache entries (warm)"));

  disk_cache::SimpleBackendImpl::FlushWorkerPoolForTesting();
  base::RunLoop().RunUntilIdle();
}

TEST_F(DiskCachePerfTest, CacheBackendPerformance) {
  CacheBackendPerformance();
}

TEST_F(DiskCachePerfTest, SimpleCacheBackendPerformance) {
  SetSimpleCacheMode();
  CacheBackendPerformance();
}

int BlockSize() {
  // We can use form 1 to 4 blocks.
  return (rand() & 0x3) + 1;
}

// Creating and deleting "entries" on a block-file is something quite frequent
// (after all, almost everything is stored on block files). The operation is
// almost free when the file is empty, but can be expensive if the file gets
// fragmented, or if we have multiple files. This test measures that scenario,
// by using multiple, highly fragmented files.
TEST_F(DiskCachePerfTest, BlockFilesPerformance) {
  ASSERT_TRUE(CleanupCacheDir());

  disk_cache::BlockFiles files(cache_path_);
  ASSERT_TRUE(files.Init(true));

  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);

  const int kNumBlocks = 60000;
  disk_cache::Addr address[kNumBlocks];

  base::PerfTimeLogger timer1("Fill three block-files");

  // Fill up the 32-byte block file (use three files).
  for (int i = 0; i < kNumBlocks; i++) {
    EXPECT_TRUE(
        files.CreateBlock(disk_cache::RANKINGS, BlockSize(), &address[i]));
  }

  timer1.Done();
  base::PerfTimeLogger timer2("Create and delete blocks");

  for (int i = 0; i < 200000; i++) {
    int entry = rand() * (kNumBlocks / RAND_MAX + 1);
    if (entry >= kNumBlocks)
      entry = 0;

    files.DeleteBlock(address[entry], false);
    EXPECT_TRUE(
        files.CreateBlock(disk_cache::RANKINGS, BlockSize(), &address[entry]));
  }

  timer2.Done();
  base::RunLoop().RunUntilIdle();
}

}  // namespace
