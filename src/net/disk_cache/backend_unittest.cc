// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/test/mock_entropy_provider.h"
#include "base/third_party/dynamic_annotations/dynamic_annotations.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "net/base/cache_type.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/entry_impl.h"
#include "net/disk_cache/blockfile/experiments.h"
#include "net/disk_cache/blockfile/histogram_macros.h"
#include "net/disk_cache/blockfile/mapped_file.h"
#include "net/disk_cache/cache_util.h"
#include "net/disk_cache/disk_cache_test_base.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/disk_cache/memory/mem_backend_impl.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_entry_format.h"
#include "net/disk_cache/simple/simple_index.h"
#include "net/disk_cache/simple/simple_synchronous_entry.h"
#include "net/disk_cache/simple/simple_test_util.h"
#include "net/disk_cache/simple/simple_util.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

#if defined(OS_WIN)
#include "base/win/scoped_handle.h"
#endif

// Provide a BackendImpl object to macros from histogram_macros.h.
#define CACHE_UMA_BACKEND_IMPL_OBJ backend_

using base::Time;

namespace {

const char kExistingEntryKey[] = "existing entry key";

std::unique_ptr<disk_cache::BackendImpl> CreateExistingEntryCache(
    const base::Thread& cache_thread,
    base::FilePath& cache_path) {
  net::TestCompletionCallback cb;

  std::unique_ptr<disk_cache::BackendImpl> cache(new disk_cache::BackendImpl(
      cache_path, cache_thread.task_runner(), NULL));
  int rv = cache->Init(cb.callback());
  if (cb.GetResult(rv) != net::OK)
    return std::unique_ptr<disk_cache::BackendImpl>();

  disk_cache::Entry* entry = NULL;
  rv = cache->CreateEntry(kExistingEntryKey, &entry, cb.callback());
  if (cb.GetResult(rv) != net::OK)
    return std::unique_ptr<disk_cache::BackendImpl>();
  entry->Close();

  return cache;
}

}  // namespace

// Tests that can run with different types of caches.
class DiskCacheBackendTest : public DiskCacheTestWithCache {
 protected:
  // Some utility methods:

  // Perform IO operations on the cache until there is pending IO.
  int GeneratePendingIO(net::TestCompletionCallback* cb);

  // Adds 5 sparse entries. |doomed_start| and |doomed_end| if not NULL,
  // will be filled with times, used by DoomEntriesSince and DoomEntriesBetween.
  // There are 4 entries after doomed_start and 2 after doomed_end.
  void InitSparseCache(base::Time* doomed_start, base::Time* doomed_end);

  bool CreateSetOfRandomEntries(std::set<std::string>* key_pool);
  bool EnumerateAndMatchKeys(int max_to_open,
                             TestIterator* iter,
                             std::set<std::string>* keys_to_match,
                             size_t* count);

  // Computes the expected size of entry metadata, i.e. the total size without
  // the actual data stored. This depends only on the entry's |key| size.
  int GetEntryMetadataSize(std::string key);

  // Actual tests:
  void BackendBasics();
  void BackendKeying();
  void BackendShutdownWithPendingFileIO(bool fast);
  void BackendShutdownWithPendingIO(bool fast);
  void BackendShutdownWithPendingCreate(bool fast);
  void BackendShutdownWithPendingDoom();
  void BackendSetSize();
  void BackendLoad();
  void BackendChain();
  void BackendValidEntry();
  void BackendInvalidEntry();
  void BackendInvalidEntryRead();
  void BackendInvalidEntryWithLoad();
  void BackendTrimInvalidEntry();
  void BackendTrimInvalidEntry2();
  void BackendEnumerations();
  void BackendEnumerations2();
  void BackendDoomMidEnumeration();
  void BackendInvalidEntryEnumeration();
  void BackendFixEnumerators();
  void BackendDoomRecent();
  void BackendDoomBetween();
  void BackendCalculateSizeOfAllEntries();
  void BackendCalculateSizeOfEntriesBetween();
  void BackendTransaction(const std::string& name, int num_entries, bool load);
  void BackendRecoverInsert();
  void BackendRecoverRemove();
  void BackendRecoverWithEviction();
  void BackendInvalidEntry2();
  void BackendInvalidEntry3();
  void BackendInvalidEntry7();
  void BackendInvalidEntry8();
  void BackendInvalidEntry9(bool eviction);
  void BackendInvalidEntry10(bool eviction);
  void BackendInvalidEntry11(bool eviction);
  void BackendTrimInvalidEntry12();
  void BackendDoomAll();
  void BackendDoomAll2();
  void BackendInvalidRankings();
  void BackendInvalidRankings2();
  void BackendDisable();
  void BackendDisable2();
  void BackendDisable3();
  void BackendDisable4();
  void BackendDisabledAPI();

  void BackendEviction();
};

int DiskCacheBackendTest::GeneratePendingIO(net::TestCompletionCallback* cb) {
  if (!use_current_thread_) {
    ADD_FAILURE();
    return net::ERR_FAILED;
  }

  disk_cache::Entry* entry;
  int rv = cache_->CreateEntry("some key", &entry, cb->callback());
  if (cb->GetResult(rv) != net::OK)
    return net::ERR_CACHE_CREATE_FAILURE;

  const int kSize = 25000;
  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kSize));
  CacheTestFillBuffer(buffer->data(), kSize, false);

  for (int i = 0; i < 10 * 1024 * 1024; i += 64 * 1024) {
    // We are using the current thread as the cache thread because we want to
    // be able to call directly this method to make sure that the OS (instead
    // of us switching thread) is returning IO pending.
    if (!simple_cache_mode_) {
      rv = static_cast<disk_cache::EntryImpl*>(entry)->WriteDataImpl(
          0, i, buffer.get(), kSize, cb->callback(), false);
    } else {
      rv = entry->WriteData(0, i, buffer.get(), kSize, cb->callback(), false);
    }

    if (rv == net::ERR_IO_PENDING)
      break;
    if (rv != kSize)
      rv = net::ERR_FAILED;
  }

  // Don't call Close() to avoid going through the queue or we'll deadlock
  // waiting for the operation to finish.
  if (!simple_cache_mode_)
    static_cast<disk_cache::EntryImpl*>(entry)->Release();
  else
    entry->Close();

  return rv;
}

void DiskCacheBackendTest::InitSparseCache(base::Time* doomed_start,
                                           base::Time* doomed_end) {
  InitCache();

  const int kSize = 50;
  // This must be greater than MemEntryImpl::kMaxSparseEntrySize.
  const int kOffset = 10 + 1024 * 1024;

  disk_cache::Entry* entry0 = NULL;
  disk_cache::Entry* entry1 = NULL;
  disk_cache::Entry* entry2 = NULL;

  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kSize));
  CacheTestFillBuffer(buffer->data(), kSize, false);

  ASSERT_THAT(CreateEntry("zeroth", &entry0), IsOk());
  ASSERT_EQ(kSize, WriteSparseData(entry0, 0, buffer.get(), kSize));
  ASSERT_EQ(kSize,
            WriteSparseData(entry0, kOffset + kSize, buffer.get(), kSize));
  entry0->Close();

  FlushQueueForTest();
  AddDelay();
  if (doomed_start)
    *doomed_start = base::Time::Now();

  // Order in rankings list:
  // first_part1, first_part2, second_part1, second_part2
  ASSERT_THAT(CreateEntry("first", &entry1), IsOk());
  ASSERT_EQ(kSize, WriteSparseData(entry1, 0, buffer.get(), kSize));
  ASSERT_EQ(kSize,
            WriteSparseData(entry1, kOffset + kSize, buffer.get(), kSize));
  entry1->Close();

  ASSERT_THAT(CreateEntry("second", &entry2), IsOk());
  ASSERT_EQ(kSize, WriteSparseData(entry2, 0, buffer.get(), kSize));
  ASSERT_EQ(kSize,
            WriteSparseData(entry2, kOffset + kSize, buffer.get(), kSize));
  entry2->Close();

  FlushQueueForTest();
  AddDelay();
  if (doomed_end)
    *doomed_end = base::Time::Now();

  // Order in rankings list:
  // third_part1, fourth_part1, third_part2, fourth_part2
  disk_cache::Entry* entry3 = NULL;
  disk_cache::Entry* entry4 = NULL;
  ASSERT_THAT(CreateEntry("third", &entry3), IsOk());
  ASSERT_EQ(kSize, WriteSparseData(entry3, 0, buffer.get(), kSize));
  ASSERT_THAT(CreateEntry("fourth", &entry4), IsOk());
  ASSERT_EQ(kSize, WriteSparseData(entry4, 0, buffer.get(), kSize));
  ASSERT_EQ(kSize,
            WriteSparseData(entry3, kOffset + kSize, buffer.get(), kSize));
  ASSERT_EQ(kSize,
            WriteSparseData(entry4, kOffset + kSize, buffer.get(), kSize));
  entry3->Close();
  entry4->Close();

  FlushQueueForTest();
  AddDelay();
}

// Creates entries based on random keys. Stores these keys in |key_pool|.
bool DiskCacheBackendTest::CreateSetOfRandomEntries(
    std::set<std::string>* key_pool) {
  const int kNumEntries = 10;
  const int initial_entry_count = cache_->GetEntryCount();

  for (int i = 0; i < kNumEntries; ++i) {
    std::string key = GenerateKey(true);
    disk_cache::Entry* entry;
    if (CreateEntry(key, &entry) != net::OK) {
      return false;
    }
    key_pool->insert(key);
    entry->Close();
  }
  return key_pool->size() ==
         static_cast<size_t>(cache_->GetEntryCount() - initial_entry_count);
}

// Performs iteration over the backend and checks that the keys of entries
// opened are in |keys_to_match|, then erases them. Up to |max_to_open| entries
// will be opened, if it is positive. Otherwise, iteration will continue until
// OpenNextEntry stops returning net::OK.
bool DiskCacheBackendTest::EnumerateAndMatchKeys(
    int max_to_open,
    TestIterator* iter,
    std::set<std::string>* keys_to_match,
    size_t* count) {
  disk_cache::Entry* entry;

  if (!iter)
    return false;
  while (iter->OpenNextEntry(&entry) == net::OK) {
    if (!entry)
      return false;
    EXPECT_EQ(1U, keys_to_match->erase(entry->GetKey()));
    entry->Close();
    ++(*count);
    if (max_to_open >= 0 && static_cast<int>(*count) >= max_to_open)
      break;
  };

  return true;
}

int DiskCacheBackendTest::GetEntryMetadataSize(std::string key) {
  // For blockfile and memory backends, it is just the key size.
  if (!simple_cache_mode_)
    return key.size();

  // For the simple cache, we must add the file header and EOF, and that for
  // every stream.
  return disk_cache::kSimpleEntryStreamCount *
         (sizeof(disk_cache::SimpleFileHeader) +
          sizeof(disk_cache::SimpleFileEOF) + key.size());
}

void DiskCacheBackendTest::BackendBasics() {
  InitCache();
  disk_cache::Entry *entry1 = NULL, *entry2 = NULL;
  EXPECT_NE(net::OK, OpenEntry("the first key", &entry1));
  ASSERT_THAT(CreateEntry("the first key", &entry1), IsOk());
  ASSERT_TRUE(NULL != entry1);
  entry1->Close();
  entry1 = NULL;
  // base::trace_event::EstimateMemoryUsage(cache_) is added to make sure
  // tracking memory doesn't introduce crashes.
  EXPECT_LT(0u, base::trace_event::EstimateMemoryUsage(cache_));

  ASSERT_THAT(OpenEntry("the first key", &entry1), IsOk());
  ASSERT_TRUE(NULL != entry1);
  entry1->Close();
  entry1 = NULL;

  EXPECT_NE(net::OK, CreateEntry("the first key", &entry1));
  ASSERT_THAT(OpenEntry("the first key", &entry1), IsOk());
  EXPECT_NE(net::OK, OpenEntry("some other key", &entry2));
  ASSERT_THAT(CreateEntry("some other key", &entry2), IsOk());
  ASSERT_TRUE(NULL != entry1);
  ASSERT_TRUE(NULL != entry2);
  EXPECT_EQ(2, cache_->GetEntryCount());
  EXPECT_LT(0u, base::trace_event::EstimateMemoryUsage(cache_));

  disk_cache::Entry* entry3 = NULL;
  ASSERT_THAT(OpenEntry("some other key", &entry3), IsOk());
  ASSERT_TRUE(NULL != entry3);
  EXPECT_TRUE(entry2 == entry3);
  EXPECT_LT(0u, base::trace_event::EstimateMemoryUsage(cache_));

  EXPECT_THAT(DoomEntry("some other key"), IsOk());
  EXPECT_EQ(1, cache_->GetEntryCount());
  entry1->Close();
  entry2->Close();
  entry3->Close();
  EXPECT_LT(0u, base::trace_event::EstimateMemoryUsage(cache_));

  EXPECT_THAT(DoomEntry("the first key"), IsOk());
  EXPECT_EQ(0, cache_->GetEntryCount());

  ASSERT_THAT(CreateEntry("the first key", &entry1), IsOk());
  ASSERT_THAT(CreateEntry("some other key", &entry2), IsOk());
  entry1->Doom();
  entry1->Close();
  EXPECT_THAT(DoomEntry("some other key"), IsOk());
  EXPECT_EQ(0, cache_->GetEntryCount());
  entry2->Close();
  EXPECT_LT(0u, base::trace_event::EstimateMemoryUsage(cache_));
}

TEST_F(DiskCacheBackendTest, Basics) {
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, NewEvictionBasics) {
  SetNewEviction();
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyBasics) {
  SetMemoryOnlyMode();
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, AppCacheBasics) {
  SetCacheType(net::APP_CACHE);
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, ShaderCacheBasics) {
  SetCacheType(net::SHADER_CACHE);
  BackendBasics();
}

void DiskCacheBackendTest::BackendKeying() {
  InitCache();
  const char kName1[] = "the first key";
  const char kName2[] = "the first Key";
  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(CreateEntry(kName1, &entry1), IsOk());

  ASSERT_THAT(CreateEntry(kName2, &entry2), IsOk());
  EXPECT_TRUE(entry1 != entry2) << "Case sensitive";
  entry2->Close();

  char buffer[30];
  base::strlcpy(buffer, kName1, arraysize(buffer));
  ASSERT_THAT(OpenEntry(buffer, &entry2), IsOk());
  EXPECT_TRUE(entry1 == entry2);
  entry2->Close();

  base::strlcpy(buffer + 1, kName1, arraysize(buffer) - 1);
  ASSERT_THAT(OpenEntry(buffer + 1, &entry2), IsOk());
  EXPECT_TRUE(entry1 == entry2);
  entry2->Close();

  base::strlcpy(buffer + 3,  kName1, arraysize(buffer) - 3);
  ASSERT_THAT(OpenEntry(buffer + 3, &entry2), IsOk());
  EXPECT_TRUE(entry1 == entry2);
  entry2->Close();

  // Now verify long keys.
  char buffer2[20000];
  memset(buffer2, 's', sizeof(buffer2));
  buffer2[1023] = '\0';
  ASSERT_EQ(net::OK, CreateEntry(buffer2, &entry2)) << "key on block file";
  entry2->Close();

  buffer2[1023] = 'g';
  buffer2[19999] = '\0';
  ASSERT_EQ(net::OK, CreateEntry(buffer2, &entry2)) << "key on external file";
  entry2->Close();
  entry1->Close();
}

TEST_F(DiskCacheBackendTest, Keying) {
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, NewEvictionKeying) {
  SetNewEviction();
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyKeying) {
  SetMemoryOnlyMode();
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, AppCacheKeying) {
  SetCacheType(net::APP_CACHE);
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, ShaderCacheKeying) {
  SetCacheType(net::SHADER_CACHE);
  BackendKeying();
}

TEST_F(DiskCacheTest, CreateBackend) {
  net::TestCompletionCallback cb;

  {
    ASSERT_TRUE(CleanupCacheDir());
    base::Thread cache_thread("CacheThread");
    ASSERT_TRUE(cache_thread.StartWithOptions(
        base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));

    // Test the private factory method(s).
    std::unique_ptr<disk_cache::Backend> cache;
    cache = disk_cache::MemBackendImpl::CreateBackend(0, NULL);
    ASSERT_TRUE(cache.get());
    cache.reset();

    // Now test the public API.
    int rv = disk_cache::CreateCacheBackend(net::DISK_CACHE,
                                            net::CACHE_BACKEND_DEFAULT,
                                            cache_path_,
                                            0,
                                            false,
                                            cache_thread.task_runner(),
                                            NULL,
                                            &cache,
                                            cb.callback());
    ASSERT_THAT(cb.GetResult(rv), IsOk());
    ASSERT_TRUE(cache.get());
    cache.reset();

    rv = disk_cache::CreateCacheBackend(net::MEMORY_CACHE,
                                        net::CACHE_BACKEND_DEFAULT,
                                        base::FilePath(), 0,
                                        false, NULL, NULL, &cache,
                                        cb.callback());
    ASSERT_THAT(cb.GetResult(rv), IsOk());
    ASSERT_TRUE(cache.get());
    cache.reset();
  }

  base::RunLoop().RunUntilIdle();
}

// Tests that |BackendImpl| fails to initialize with a missing file.
TEST_F(DiskCacheBackendTest, CreateBackend_MissingFile) {
  ASSERT_TRUE(CopyTestCache("bad_entry"));
  base::FilePath filename = cache_path_.AppendASCII("data_1");
  base::DeleteFile(filename, false);
  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
      base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));
  net::TestCompletionCallback cb;

  bool prev = base::ThreadRestrictions::SetIOAllowed(false);
  std::unique_ptr<disk_cache::BackendImpl> cache(new disk_cache::BackendImpl(
      cache_path_, cache_thread.task_runner(), NULL));
  int rv = cache->Init(cb.callback());
  EXPECT_THAT(cb.GetResult(rv), IsError(net::ERR_FAILED));
  base::ThreadRestrictions::SetIOAllowed(prev);

  cache.reset();
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, ExternalFiles) {
  InitCache();
  // First, let's create a file on the folder.
  base::FilePath filename = cache_path_.AppendASCII("f_000001");

  const int kSize = 50;
  scoped_refptr<net::IOBuffer> buffer1(new net::IOBuffer(kSize));
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  ASSERT_EQ(kSize, base::WriteFile(filename, buffer1->data(), kSize));

  // Now let's create a file with the cache.
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("key", &entry), IsOk());
  ASSERT_EQ(0, WriteData(entry, 0, 20000, buffer1.get(), 0, false));
  entry->Close();

  // And verify that the first file is still there.
  scoped_refptr<net::IOBuffer> buffer2(new net::IOBuffer(kSize));
  ASSERT_EQ(kSize, base::ReadFile(filename, buffer2->data(), kSize));
  EXPECT_EQ(0, memcmp(buffer1->data(), buffer2->data(), kSize));
}

// Tests that we deal with file-level pending operations at destruction time.
void DiskCacheBackendTest::BackendShutdownWithPendingFileIO(bool fast) {
  ASSERT_TRUE(CleanupCacheDir());
  uint32_t flags = disk_cache::kNoBuffering;
  if (!fast)
    flags |= disk_cache::kNoRandom;

  UseCurrentThread();
  CreateBackend(flags, NULL);

  net::TestCompletionCallback cb;
  int rv = GeneratePendingIO(&cb);

  // The cache destructor will see one pending operation here.
  cache_.reset();

  if (rv == net::ERR_IO_PENDING) {
    if (fast || simple_cache_mode_)
      EXPECT_FALSE(cb.have_result());
    else
      EXPECT_TRUE(cb.have_result());
  }

  base::RunLoop().RunUntilIdle();

#if !defined(OS_IOS)
  // Wait for the actual operation to complete, or we'll keep a file handle that
  // may cause issues later. Note that on iOS systems even though this test
  // uses a single thread, the actual IO is posted to a worker thread and the
  // cache destructor breaks the link to reach cb when the operation completes.
  rv = cb.GetResult(rv);
#endif
}

TEST_F(DiskCacheBackendTest, ShutdownWithPendingFileIO) {
  BackendShutdownWithPendingFileIO(false);
}

// Here and below, tests that simulate crashes are not compiled in LeakSanitizer
// builds because they contain a lot of intentional memory leaks.
// The wrapper scripts used to run tests under Valgrind Memcheck will also
// disable these tests. See:
// tools/valgrind/gtest_exclude/net_unittests.gtest-memcheck.txt
#if !defined(LEAK_SANITIZER)
// We'll be leaking from this test.
TEST_F(DiskCacheBackendTest, ShutdownWithPendingFileIO_Fast) {
  // The integrity test sets kNoRandom so there's a version mismatch if we don't
  // force new eviction.
  SetNewEviction();
  BackendShutdownWithPendingFileIO(true);
}
#endif

// See crbug.com/330074
#if !defined(OS_IOS)
// Tests that one cache instance is not affected by another one going away.
TEST_F(DiskCacheBackendTest, MultipleInstancesWithPendingFileIO) {
  base::ScopedTempDir store;
  ASSERT_TRUE(store.CreateUniqueTempDir());

  net::TestCompletionCallback cb;
  std::unique_ptr<disk_cache::Backend> extra_cache;
  int rv = disk_cache::CreateCacheBackend(
      net::DISK_CACHE, net::CACHE_BACKEND_DEFAULT, store.GetPath(), 0, false,
      base::ThreadTaskRunnerHandle::Get(), NULL, &extra_cache, cb.callback());
  ASSERT_THAT(cb.GetResult(rv), IsOk());
  ASSERT_TRUE(extra_cache.get() != NULL);

  ASSERT_TRUE(CleanupCacheDir());
  SetNewEviction();  // Match the expected behavior for integrity verification.
  UseCurrentThread();

  CreateBackend(disk_cache::kNoBuffering, NULL);
  rv = GeneratePendingIO(&cb);

  // cache_ has a pending operation, and extra_cache will go away.
  extra_cache.reset();

  if (rv == net::ERR_IO_PENDING)
    EXPECT_FALSE(cb.have_result());

  base::RunLoop().RunUntilIdle();

  // Wait for the actual operation to complete, or we'll keep a file handle that
  // may cause issues later.
  rv = cb.GetResult(rv);
}
#endif

// Tests that we deal with background-thread pending operations.
void DiskCacheBackendTest::BackendShutdownWithPendingIO(bool fast) {
  net::TestCompletionCallback cb;

  {
    ASSERT_TRUE(CleanupCacheDir());
    base::Thread cache_thread("CacheThread");
    ASSERT_TRUE(cache_thread.StartWithOptions(
        base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));

    uint32_t flags = disk_cache::kNoBuffering;
    if (!fast)
      flags |= disk_cache::kNoRandom;

    CreateBackend(flags, &cache_thread);

    disk_cache::Entry* entry;
    int rv = cache_->CreateEntry("some key", &entry, cb.callback());
    ASSERT_THAT(cb.GetResult(rv), IsOk());

    entry->Close();

    // The cache destructor will see one pending operation here.
    cache_.reset();
  }

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(cb.have_result());
}

TEST_F(DiskCacheBackendTest, ShutdownWithPendingIO) {
  BackendShutdownWithPendingIO(false);
}

#if !defined(LEAK_SANITIZER)
// We'll be leaking from this test.
TEST_F(DiskCacheBackendTest, ShutdownWithPendingIO_Fast) {
  // The integrity test sets kNoRandom so there's a version mismatch if we don't
  // force new eviction.
  SetNewEviction();
  BackendShutdownWithPendingIO(true);
}
#endif

// Tests that we deal with create-type pending operations.
void DiskCacheBackendTest::BackendShutdownWithPendingCreate(bool fast) {
  net::TestCompletionCallback cb;

  {
    ASSERT_TRUE(CleanupCacheDir());
    base::Thread cache_thread("CacheThread");
    ASSERT_TRUE(cache_thread.StartWithOptions(
        base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));

    disk_cache::BackendFlags flags =
      fast ? disk_cache::kNone : disk_cache::kNoRandom;
    CreateBackend(flags, &cache_thread);

    disk_cache::Entry* entry;
    int rv = cache_->CreateEntry("some key", &entry, cb.callback());
    ASSERT_THAT(rv, IsError(net::ERR_IO_PENDING));

    cache_.reset();
    EXPECT_FALSE(cb.have_result());
  }

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(cb.have_result());
}

TEST_F(DiskCacheBackendTest, ShutdownWithPendingCreate) {
  BackendShutdownWithPendingCreate(false);
}

#if !defined(LEAK_SANITIZER)
// We'll be leaking an entry from this test.
TEST_F(DiskCacheBackendTest, ShutdownWithPendingCreate_Fast) {
  // The integrity test sets kNoRandom so there's a version mismatch if we don't
  // force new eviction.
  SetNewEviction();
  BackendShutdownWithPendingCreate(true);
}
#endif

void DiskCacheBackendTest::BackendShutdownWithPendingDoom() {
  net::TestCompletionCallback cb;
  {
    ASSERT_TRUE(CleanupCacheDir());
    base::Thread cache_thread("CacheThread");
    ASSERT_TRUE(cache_thread.StartWithOptions(
        base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));

    disk_cache::BackendFlags flags = disk_cache::kNoRandom;
    CreateBackend(flags, &cache_thread);

    disk_cache::Entry* entry;
    int rv = cache_->CreateEntry("some key", &entry, cb.callback());
    ASSERT_THAT(cb.GetResult(rv), IsOk());
    entry->Close();
    entry = nullptr;

    rv = cache_->DoomEntry("some key", cb.callback());
    ASSERT_THAT(rv, IsError(net::ERR_IO_PENDING));

    cache_.reset();
    EXPECT_FALSE(cb.have_result());
  }

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(cb.have_result());
}

TEST_F(DiskCacheBackendTest, ShutdownWithPendingDoom) {
  BackendShutdownWithPendingDoom();
}

// Disabled on android since this test requires cache creator to create
// blockfile caches.
#if !defined(OS_ANDROID)
TEST_F(DiskCacheTest, TruncatedIndex) {
  ASSERT_TRUE(CleanupCacheDir());
  base::FilePath index = cache_path_.AppendASCII("index");
  ASSERT_EQ(5, base::WriteFile(index, "hello", 5));

  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
      base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));
  net::TestCompletionCallback cb;

  std::unique_ptr<disk_cache::Backend> backend;
  int rv = disk_cache::CreateCacheBackend(net::DISK_CACHE,
                                          net::CACHE_BACKEND_BLOCKFILE,
                                          cache_path_,
                                          0,
                                          false,
                                          cache_thread.task_runner(),
                                          NULL,
                                          &backend,
                                          cb.callback());
  ASSERT_NE(net::OK, cb.GetResult(rv));

  ASSERT_FALSE(backend);
}
#endif

void DiskCacheBackendTest::BackendSetSize() {
  const int cache_size = 0x10000;  // 64 kB
  SetMaxSize(cache_size);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());

  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(cache_size));
  memset(buffer->data(), 0, cache_size);
  EXPECT_EQ(cache_size / 10,
            WriteData(entry, 0, 0, buffer.get(), cache_size / 10, false))
      << "normal file";

  EXPECT_EQ(net::ERR_FAILED,
            WriteData(entry, 1, 0, buffer.get(), cache_size / 5, false))
      << "file size above the limit";

  // By doubling the total size, we make this file cacheable.
  SetMaxSize(cache_size * 2);
  EXPECT_EQ(cache_size / 5,
            WriteData(entry, 1, 0, buffer.get(), cache_size / 5, false));

  // Let's fill up the cache!.
  SetMaxSize(cache_size * 10);
  EXPECT_EQ(cache_size * 3 / 4,
            WriteData(entry, 0, 0, buffer.get(), cache_size * 3 / 4, false));
  entry->Close();
  FlushQueueForTest();

  SetMaxSize(cache_size);

  // The cache is 95% full.

  ASSERT_THAT(CreateEntry(second, &entry), IsOk());
  EXPECT_EQ(cache_size / 10,
            WriteData(entry, 0, 0, buffer.get(), cache_size / 10, false));

  disk_cache::Entry* entry2;
  ASSERT_THAT(CreateEntry("an extra key", &entry2), IsOk());
  EXPECT_EQ(cache_size / 10,
            WriteData(entry2, 0, 0, buffer.get(), cache_size / 10, false));
  entry2->Close();  // This will trigger the cache trim.

  EXPECT_NE(net::OK, OpenEntry(first, &entry2));

  FlushQueueForTest();  // Make sure that we are done trimming the cache.
  FlushQueueForTest();  // We may have posted two tasks to evict stuff.

  entry->Close();
  ASSERT_THAT(OpenEntry(second, &entry), IsOk());
  EXPECT_EQ(cache_size / 10, entry->GetDataSize(0));
  entry->Close();
}

TEST_F(DiskCacheBackendTest, SetSize) {
  BackendSetSize();
}

TEST_F(DiskCacheBackendTest, NewEvictionSetSize) {
  SetNewEviction();
  BackendSetSize();
}

TEST_F(DiskCacheBackendTest, MemoryOnlySetSize) {
  SetMemoryOnlyMode();
  BackendSetSize();
}

void DiskCacheBackendTest::BackendLoad() {
  InitCache();
  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);

  disk_cache::Entry* entries[100];
  for (int i = 0; i < 100; i++) {
    std::string key = GenerateKey(true);
    ASSERT_THAT(CreateEntry(key, &entries[i]), IsOk());
  }
  EXPECT_EQ(100, cache_->GetEntryCount());

  for (int i = 0; i < 100; i++) {
    int source1 = rand() % 100;
    int source2 = rand() % 100;
    disk_cache::Entry* temp = entries[source1];
    entries[source1] = entries[source2];
    entries[source2] = temp;
  }

  for (int i = 0; i < 100; i++) {
    disk_cache::Entry* entry;
    ASSERT_THAT(OpenEntry(entries[i]->GetKey(), &entry), IsOk());
    EXPECT_TRUE(entry == entries[i]);
    entry->Close();
    entries[i]->Doom();
    entries[i]->Close();
  }
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, Load) {
  // Work with a tiny index table (16 entries)
  SetMask(0xf);
  SetMaxSize(0x100000);
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, NewEvictionLoad) {
  SetNewEviction();
  // Work with a tiny index table (16 entries)
  SetMask(0xf);
  SetMaxSize(0x100000);
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyLoad) {
  SetMaxSize(0x100000);
  SetMemoryOnlyMode();
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, AppCacheLoad) {
  SetCacheType(net::APP_CACHE);
  // Work with a tiny index table (16 entries)
  SetMask(0xf);
  SetMaxSize(0x100000);
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, ShaderCacheLoad) {
  SetCacheType(net::SHADER_CACHE);
  // Work with a tiny index table (16 entries)
  SetMask(0xf);
  SetMaxSize(0x100000);
  BackendLoad();
}

// Tests the chaining of an entry to the current head.
void DiskCacheBackendTest::BackendChain() {
  SetMask(0x1);  // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  InitCache();

  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("The first key", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("The Second key", &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheBackendTest, Chain) {
  BackendChain();
}

TEST_F(DiskCacheBackendTest, NewEvictionChain) {
  SetNewEviction();
  BackendChain();
}

TEST_F(DiskCacheBackendTest, AppCacheChain) {
  SetCacheType(net::APP_CACHE);
  BackendChain();
}

TEST_F(DiskCacheBackendTest, ShaderCacheChain) {
  SetCacheType(net::SHADER_CACHE);
  BackendChain();
}

TEST_F(DiskCacheBackendTest, NewEvictionTrim) {
  SetNewEviction();
  InitCache();

  disk_cache::Entry* entry;
  for (int i = 0; i < 100; i++) {
    std::string name(base::StringPrintf("Key %d", i));
    ASSERT_THAT(CreateEntry(name, &entry), IsOk());
    entry->Close();
    if (i < 90) {
      // Entries 0 to 89 are in list 1; 90 to 99 are in list 0.
      ASSERT_THAT(OpenEntry(name, &entry), IsOk());
      entry->Close();
    }
  }

  // The first eviction must come from list 1 (10% limit), the second must come
  // from list 0.
  TrimForTest(false);
  EXPECT_NE(net::OK, OpenEntry("Key 0", &entry));
  TrimForTest(false);
  EXPECT_NE(net::OK, OpenEntry("Key 90", &entry));

  // Double check that we still have the list tails.
  ASSERT_THAT(OpenEntry("Key 1", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(OpenEntry("Key 91", &entry), IsOk());
  entry->Close();
}

// Before looking for invalid entries, let's check a valid entry.
void DiskCacheBackendTest::BackendValidEntry() {
  InitCache();

  std::string key("Some key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 50;
  scoped_refptr<net::IOBuffer> buffer1(new net::IOBuffer(kSize));
  memset(buffer1->data(), 0, kSize);
  base::strlcpy(buffer1->data(), "And the data to save", kSize);
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer1.get(), kSize, false));
  entry->Close();
  SimulateCrash();

  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  scoped_refptr<net::IOBuffer> buffer2(new net::IOBuffer(kSize));
  memset(buffer2->data(), 0, kSize);
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, buffer2.get(), kSize));
  entry->Close();
  EXPECT_STREQ(buffer1->data(), buffer2->data());
}

TEST_F(DiskCacheBackendTest, ValidEntry) {
  BackendValidEntry();
}

TEST_F(DiskCacheBackendTest, NewEvictionValidEntry) {
  SetNewEviction();
  BackendValidEntry();
}

// The same logic of the previous test (ValidEntry), but this time force the
// entry to be invalid, simulating a crash in the middle.
// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendInvalidEntry() {
  InitCache();

  std::string key("Some key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 50;
  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kSize));
  memset(buffer->data(), 0, kSize);
  base::strlcpy(buffer->data(), "And the data to save", kSize);
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));
  SimulateCrash();

  EXPECT_NE(net::OK, OpenEntry(key, &entry));
  EXPECT_EQ(0, cache_->GetEntryCount());
}

#if !defined(LEAK_SANITIZER)
// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, InvalidEntry) {
  BackendInvalidEntry();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry) {
  SetNewEviction();
  BackendInvalidEntry();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, AppCacheInvalidEntry) {
  SetCacheType(net::APP_CACHE);
  BackendInvalidEntry();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, ShaderCacheInvalidEntry) {
  SetCacheType(net::SHADER_CACHE);
  BackendInvalidEntry();
}

// Almost the same test, but this time crash the cache after reading an entry.
// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendInvalidEntryRead() {
  InitCache();

  std::string key("Some key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 50;
  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kSize));
  memset(buffer->data(), 0, kSize);
  base::strlcpy(buffer->data(), "And the data to save", kSize);
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, buffer.get(), kSize));

  SimulateCrash();

  if (type_ == net::APP_CACHE) {
    // Reading an entry and crashing should not make it dirty.
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    EXPECT_EQ(1, cache_->GetEntryCount());
    entry->Close();
  } else {
    EXPECT_NE(net::OK, OpenEntry(key, &entry));
    EXPECT_EQ(0, cache_->GetEntryCount());
  }
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, InvalidEntryRead) {
  BackendInvalidEntryRead();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntryRead) {
  SetNewEviction();
  BackendInvalidEntryRead();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, AppCacheInvalidEntryRead) {
  SetCacheType(net::APP_CACHE);
  BackendInvalidEntryRead();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, ShaderCacheInvalidEntryRead) {
  SetCacheType(net::SHADER_CACHE);
  BackendInvalidEntryRead();
}

// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendInvalidEntryWithLoad() {
  // Work with a tiny index table (16 entries)
  SetMask(0xf);
  SetMaxSize(0x100000);
  InitCache();

  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);

  const int kNumEntries = 100;
  disk_cache::Entry* entries[kNumEntries];
  for (int i = 0; i < kNumEntries; i++) {
    std::string key = GenerateKey(true);
    ASSERT_THAT(CreateEntry(key, &entries[i]), IsOk());
  }
  EXPECT_EQ(kNumEntries, cache_->GetEntryCount());

  for (int i = 0; i < kNumEntries; i++) {
    int source1 = rand() % kNumEntries;
    int source2 = rand() % kNumEntries;
    disk_cache::Entry* temp = entries[source1];
    entries[source1] = entries[source2];
    entries[source2] = temp;
  }

  std::string keys[kNumEntries];
  for (int i = 0; i < kNumEntries; i++) {
    keys[i] = entries[i]->GetKey();
    if (i < kNumEntries / 2)
      entries[i]->Close();
  }

  SimulateCrash();

  for (int i = kNumEntries / 2; i < kNumEntries; i++) {
    disk_cache::Entry* entry;
    EXPECT_NE(net::OK, OpenEntry(keys[i], &entry));
  }

  for (int i = 0; i < kNumEntries / 2; i++) {
    disk_cache::Entry* entry;
    ASSERT_THAT(OpenEntry(keys[i], &entry), IsOk());
    entry->Close();
  }

  EXPECT_EQ(kNumEntries / 2, cache_->GetEntryCount());
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, InvalidEntryWithLoad) {
  BackendInvalidEntryWithLoad();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntryWithLoad) {
  SetNewEviction();
  BackendInvalidEntryWithLoad();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, AppCacheInvalidEntryWithLoad) {
  SetCacheType(net::APP_CACHE);
  BackendInvalidEntryWithLoad();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, ShaderCacheInvalidEntryWithLoad) {
  SetCacheType(net::SHADER_CACHE);
  BackendInvalidEntryWithLoad();
}

// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendTrimInvalidEntry() {
  const int kSize = 0x3000;  // 12 kB
  SetMaxSize(kSize * 10);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());

  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kSize));
  memset(buffer->data(), 0, kSize);
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));

  // Simulate a crash.
  SimulateCrash();

  ASSERT_THAT(CreateEntry(second, &entry), IsOk());
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));

  EXPECT_EQ(2, cache_->GetEntryCount());
  SetMaxSize(kSize);
  entry->Close();  // Trim the cache.
  FlushQueueForTest();

  // If we evicted the entry in less than 20mS, we have one entry in the cache;
  // if it took more than that, we posted a task and we'll delete the second
  // entry too.
  base::RunLoop().RunUntilIdle();

  // This may be not thread-safe in general, but for now it's OK so add some
  // ThreadSanitizer annotations to ignore data races on cache_.
  // See http://crbug.com/55970
  ANNOTATE_IGNORE_READS_BEGIN();
  EXPECT_GE(1, cache_->GetEntryCount());
  ANNOTATE_IGNORE_READS_END();

  EXPECT_NE(net::OK, OpenEntry(first, &entry));
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, TrimInvalidEntry) {
  BackendTrimInvalidEntry();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionTrimInvalidEntry) {
  SetNewEviction();
  BackendTrimInvalidEntry();
}

// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendTrimInvalidEntry2() {
  SetMask(0xf);  // 16-entry table.

  const int kSize = 0x3000;  // 12 kB
  SetMaxSize(kSize * 40);
  InitCache();

  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kSize));
  memset(buffer->data(), 0, kSize);
  disk_cache::Entry* entry;

  // Writing 32 entries to this cache chains most of them.
  for (int i = 0; i < 32; i++) {
    std::string key(base::StringPrintf("some key %d", i));
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));
    entry->Close();
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    // Note that we are not closing the entries.
  }

  // Simulate a crash.
  SimulateCrash();

  ASSERT_THAT(CreateEntry("Something else", &entry), IsOk());
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));

  FlushQueueForTest();
  EXPECT_EQ(33, cache_->GetEntryCount());
  SetMaxSize(kSize);

  // For the new eviction code, all corrupt entries are on the second list so
  // they are not going away that easy.
  if (new_eviction_) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
  }

  entry->Close();  // Trim the cache.
  FlushQueueForTest();

  // We may abort the eviction before cleaning up everything.
  base::RunLoop().RunUntilIdle();
  FlushQueueForTest();
  // If it's not clear enough: we may still have eviction tasks running at this
  // time, so the number of entries is changing while we read it.
  ANNOTATE_IGNORE_READS_AND_WRITES_BEGIN();
  EXPECT_GE(30, cache_->GetEntryCount());
  ANNOTATE_IGNORE_READS_AND_WRITES_END();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, TrimInvalidEntry2) {
  BackendTrimInvalidEntry2();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionTrimInvalidEntry2) {
  SetNewEviction();
  BackendTrimInvalidEntry2();
}
#endif  // !defined(LEAK_SANITIZER)

void DiskCacheBackendTest::BackendEnumerations() {
  InitCache();
  Time initial = Time::Now();

  const int kNumEntries = 100;
  for (int i = 0; i < kNumEntries; i++) {
    std::string key = GenerateKey(true);
    disk_cache::Entry* entry;
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    entry->Close();
  }
  EXPECT_EQ(kNumEntries, cache_->GetEntryCount());
  Time final = Time::Now();

  disk_cache::Entry* entry;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  int count = 0;
  Time last_modified[kNumEntries];
  Time last_used[kNumEntries];
  while (iter->OpenNextEntry(&entry) == net::OK) {
    ASSERT_TRUE(NULL != entry);
    if (count < kNumEntries) {
      last_modified[count] = entry->GetLastModified();
      last_used[count] = entry->GetLastUsed();
      EXPECT_TRUE(initial <= last_modified[count]);
      EXPECT_TRUE(final >= last_modified[count]);
    }

    entry->Close();
    count++;
  };
  EXPECT_EQ(kNumEntries, count);

  iter = CreateIterator();
  count = 0;
  // The previous enumeration should not have changed the timestamps.
  while (iter->OpenNextEntry(&entry) == net::OK) {
    ASSERT_TRUE(NULL != entry);
    if (count < kNumEntries) {
      EXPECT_TRUE(last_modified[count] == entry->GetLastModified());
      EXPECT_TRUE(last_used[count] == entry->GetLastUsed());
    }
    entry->Close();
    count++;
  };
  EXPECT_EQ(kNumEntries, count);
}

TEST_F(DiskCacheBackendTest, Enumerations) {
  BackendEnumerations();
}

TEST_F(DiskCacheBackendTest, NewEvictionEnumerations) {
  SetNewEviction();
  BackendEnumerations();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyEnumerations) {
  SetMemoryOnlyMode();
  BackendEnumerations();
}

TEST_F(DiskCacheBackendTest, ShaderCacheEnumerations) {
  SetCacheType(net::SHADER_CACHE);
  BackendEnumerations();
}

TEST_F(DiskCacheBackendTest, AppCacheEnumerations) {
  SetCacheType(net::APP_CACHE);
  BackendEnumerations();
}

// Verifies enumerations while entries are open.
void DiskCacheBackendTest::BackendEnumerations2() {
  InitCache();
  const std::string first("first");
  const std::string second("second");
  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(CreateEntry(first, &entry1), IsOk());
  entry1->Close();
  ASSERT_THAT(CreateEntry(second, &entry2), IsOk());
  entry2->Close();
  FlushQueueForTest();

  // Make sure that the timestamp is not the same.
  AddDelay();
  ASSERT_THAT(OpenEntry(second, &entry1), IsOk());
  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry2), IsOk());
  EXPECT_EQ(entry2->GetKey(), second);

  // Two entries and the iterator pointing at "first".
  entry1->Close();
  entry2->Close();

  // The iterator should still be valid, so we should not crash.
  ASSERT_THAT(iter->OpenNextEntry(&entry2), IsOk());
  EXPECT_EQ(entry2->GetKey(), first);
  entry2->Close();
  iter = CreateIterator();

  // Modify the oldest entry and get the newest element.
  ASSERT_THAT(OpenEntry(first, &entry1), IsOk());
  EXPECT_EQ(0, WriteData(entry1, 0, 200, NULL, 0, false));
  ASSERT_THAT(iter->OpenNextEntry(&entry2), IsOk());
  if (type_ == net::APP_CACHE) {
    // The list is not updated.
    EXPECT_EQ(entry2->GetKey(), second);
  } else {
    EXPECT_EQ(entry2->GetKey(), first);
  }

  entry1->Close();
  entry2->Close();
}

TEST_F(DiskCacheBackendTest, Enumerations2) {
  BackendEnumerations2();
}

TEST_F(DiskCacheBackendTest, NewEvictionEnumerations2) {
  SetNewEviction();
  BackendEnumerations2();
}

TEST_F(DiskCacheBackendTest, AppCacheEnumerations2) {
  SetCacheType(net::APP_CACHE);
  BackendEnumerations2();
}

TEST_F(DiskCacheBackendTest, ShaderCacheEnumerations2) {
  SetCacheType(net::SHADER_CACHE);
  BackendEnumerations2();
}

void DiskCacheBackendTest::BackendDoomMidEnumeration() {
  InitCache();

  const int kNumEntries = 100;
  std::set<std::string> keys;
  for (int i = 0; i < kNumEntries; i++) {
    std::string key = GenerateKey(true);
    keys.insert(key);
    disk_cache::Entry* entry;
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    entry->Close();
  }

  disk_cache::Entry* entry;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  int count = 0;
  while (iter->OpenNextEntry(&entry) == net::OK) {
    if (count == 0) {
      // Delete a random entry from the cache while in the midst of iteration.
      auto key_to_doom = keys.begin();
      while (*key_to_doom == entry->GetKey())
        key_to_doom++;
      ASSERT_THAT(DoomEntry(*key_to_doom), IsOk());
      ASSERT_EQ(1u, keys.erase(*key_to_doom));
    }
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(1u, keys.erase(entry->GetKey()));
    entry->Close();
    count++;
  };

  EXPECT_EQ(kNumEntries - 1, cache_->GetEntryCount());
  EXPECT_EQ(0u, keys.size());
}

TEST_F(DiskCacheBackendTest, DoomEnumerations) {
  BackendDoomMidEnumeration();
}

TEST_F(DiskCacheBackendTest, NewEvictionDoomEnumerations) {
  SetNewEviction();
  BackendDoomMidEnumeration();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomEnumerations) {
  SetMemoryOnlyMode();
  BackendDoomMidEnumeration();
}

TEST_F(DiskCacheBackendTest, ShaderCacheDoomEnumerations) {
  SetCacheType(net::SHADER_CACHE);
  BackendDoomMidEnumeration();
}

TEST_F(DiskCacheBackendTest, AppCacheDoomEnumerations) {
  SetCacheType(net::APP_CACHE);
  BackendDoomMidEnumeration();
}

TEST_F(DiskCacheBackendTest, SimpleDoomEnumerations) {
  SetSimpleCacheMode();
  BackendDoomMidEnumeration();
}

// Verify that ReadData calls do not update the LRU cache
// when using the SHADER_CACHE type.
TEST_F(DiskCacheBackendTest, ShaderCacheEnumerationReadData) {
  SetCacheType(net::SHADER_CACHE);
  InitCache();
  const std::string first("first");
  const std::string second("second");
  disk_cache::Entry *entry1, *entry2;
  const int kSize = 50;
  scoped_refptr<net::IOBuffer> buffer1(new net::IOBuffer(kSize));

  ASSERT_THAT(CreateEntry(first, &entry1), IsOk());
  memset(buffer1->data(), 0, kSize);
  base::strlcpy(buffer1->data(), "And the data to save", kSize);
  EXPECT_EQ(kSize, WriteData(entry1, 0, 0, buffer1.get(), kSize, false));

  ASSERT_THAT(CreateEntry(second, &entry2), IsOk());
  entry2->Close();

  FlushQueueForTest();

  // Make sure that the timestamp is not the same.
  AddDelay();

  // Read from the last item in the LRU.
  EXPECT_EQ(kSize, ReadData(entry1, 0, 0, buffer1.get(), kSize));
  entry1->Close();

  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry2), IsOk());
  EXPECT_EQ(entry2->GetKey(), second);
  entry2->Close();
}

#if !defined(LEAK_SANITIZER)
// Verify handling of invalid entries while doing enumerations.
// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendInvalidEntryEnumeration() {
  InitCache();

  std::string key("Some key");
  disk_cache::Entry *entry, *entry1, *entry2;
  ASSERT_THAT(CreateEntry(key, &entry1), IsOk());

  const int kSize = 50;
  scoped_refptr<net::IOBuffer> buffer1(new net::IOBuffer(kSize));
  memset(buffer1->data(), 0, kSize);
  base::strlcpy(buffer1->data(), "And the data to save", kSize);
  EXPECT_EQ(kSize, WriteData(entry1, 0, 0, buffer1.get(), kSize, false));
  entry1->Close();
  ASSERT_THAT(OpenEntry(key, &entry1), IsOk());
  EXPECT_EQ(kSize, ReadData(entry1, 0, 0, buffer1.get(), kSize));

  std::string key2("Another key");
  ASSERT_THAT(CreateEntry(key2, &entry2), IsOk());
  entry2->Close();
  ASSERT_EQ(2, cache_->GetEntryCount());

  SimulateCrash();

  std::unique_ptr<TestIterator> iter = CreateIterator();
  int count = 0;
  while (iter->OpenNextEntry(&entry) == net::OK) {
    ASSERT_TRUE(NULL != entry);
    EXPECT_EQ(key2, entry->GetKey());
    entry->Close();
    count++;
  };
  EXPECT_EQ(1, count);
  EXPECT_EQ(1, cache_->GetEntryCount());
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, InvalidEntryEnumeration) {
  BackendInvalidEntryEnumeration();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntryEnumeration) {
  SetNewEviction();
  BackendInvalidEntryEnumeration();
}
#endif  // !defined(LEAK_SANITIZER)

// Tests that if for some reason entries are modified close to existing cache
// iterators, we don't generate fatal errors or reset the cache.
void DiskCacheBackendTest::BackendFixEnumerators() {
  InitCache();

  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);

  const int kNumEntries = 10;
  for (int i = 0; i < kNumEntries; i++) {
    std::string key = GenerateKey(true);
    disk_cache::Entry* entry;
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    entry->Close();
  }
  EXPECT_EQ(kNumEntries, cache_->GetEntryCount());

  disk_cache::Entry *entry1, *entry2;
  std::unique_ptr<TestIterator> iter1 = CreateIterator(),
                                iter2 = CreateIterator();
  ASSERT_THAT(iter1->OpenNextEntry(&entry1), IsOk());
  ASSERT_TRUE(NULL != entry1);
  entry1->Close();
  entry1 = NULL;

  // Let's go to the middle of the list.
  for (int i = 0; i < kNumEntries / 2; i++) {
    if (entry1)
      entry1->Close();
    ASSERT_THAT(iter1->OpenNextEntry(&entry1), IsOk());
    ASSERT_TRUE(NULL != entry1);

    ASSERT_THAT(iter2->OpenNextEntry(&entry2), IsOk());
    ASSERT_TRUE(NULL != entry2);
    entry2->Close();
  }

  // Messing up with entry1 will modify entry2->next.
  entry1->Doom();
  ASSERT_THAT(iter2->OpenNextEntry(&entry2), IsOk());
  ASSERT_TRUE(NULL != entry2);

  // The link entry2->entry1 should be broken.
  EXPECT_NE(entry2->GetKey(), entry1->GetKey());
  entry1->Close();
  entry2->Close();

  // And the second iterator should keep working.
  ASSERT_THAT(iter2->OpenNextEntry(&entry2), IsOk());
  ASSERT_TRUE(NULL != entry2);
  entry2->Close();
}

TEST_F(DiskCacheBackendTest, FixEnumerators) {
  BackendFixEnumerators();
}

TEST_F(DiskCacheBackendTest, NewEvictionFixEnumerators) {
  SetNewEviction();
  BackendFixEnumerators();
}

void DiskCacheBackendTest::BackendDoomRecent() {
  InitCache();

  disk_cache::Entry *entry;
  ASSERT_THAT(CreateEntry("first", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("second", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time middle = Time::Now();

  ASSERT_THAT(CreateEntry("third", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("fourth", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time final = Time::Now();

  ASSERT_EQ(4, cache_->GetEntryCount());
  EXPECT_THAT(DoomEntriesSince(final), IsOk());
  ASSERT_EQ(4, cache_->GetEntryCount());

  EXPECT_THAT(DoomEntriesSince(middle), IsOk());
  ASSERT_EQ(2, cache_->GetEntryCount());

  ASSERT_THAT(OpenEntry("second", &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheBackendTest, DoomRecent) {
  BackendDoomRecent();
}

TEST_F(DiskCacheBackendTest, NewEvictionDoomRecent) {
  SetNewEviction();
  BackendDoomRecent();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomRecent) {
  SetMemoryOnlyMode();
  BackendDoomRecent();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomEntriesSinceSparse) {
  SetMemoryOnlyMode();
  base::Time start;
  InitSparseCache(&start, NULL);
  DoomEntriesSince(start);
  EXPECT_EQ(1, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DoomEntriesSinceSparse) {
  base::Time start;
  InitSparseCache(&start, NULL);
  DoomEntriesSince(start);
  // NOTE: BackendImpl counts child entries in its GetEntryCount(), while
  // MemBackendImpl does not. Thats why expected value differs here from
  // MemoryOnlyDoomEntriesSinceSparse.
  EXPECT_EQ(3, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomAllSparse) {
  SetMemoryOnlyMode();
  InitSparseCache(NULL, NULL);
  EXPECT_THAT(DoomAllEntries(), IsOk());
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DoomAllSparse) {
  InitSparseCache(NULL, NULL);
  EXPECT_THAT(DoomAllEntries(), IsOk());
  EXPECT_EQ(0, cache_->GetEntryCount());
}

void DiskCacheBackendTest::BackendDoomBetween() {
  InitCache();

  disk_cache::Entry *entry;
  ASSERT_THAT(CreateEntry("first", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time middle_start = Time::Now();

  ASSERT_THAT(CreateEntry("second", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("third", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time middle_end = Time::Now();

  ASSERT_THAT(CreateEntry("fourth", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(OpenEntry("fourth", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time final = Time::Now();

  ASSERT_EQ(4, cache_->GetEntryCount());
  EXPECT_THAT(DoomEntriesBetween(middle_start, middle_end), IsOk());
  ASSERT_EQ(2, cache_->GetEntryCount());

  ASSERT_THAT(OpenEntry("fourth", &entry), IsOk());
  entry->Close();

  EXPECT_THAT(DoomEntriesBetween(middle_start, final), IsOk());
  ASSERT_EQ(1, cache_->GetEntryCount());

  ASSERT_THAT(OpenEntry("first", &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheBackendTest, DoomBetween) {
  BackendDoomBetween();
}

TEST_F(DiskCacheBackendTest, NewEvictionDoomBetween) {
  SetNewEviction();
  BackendDoomBetween();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomBetween) {
  SetMemoryOnlyMode();
  BackendDoomBetween();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomEntriesBetweenSparse) {
  SetMemoryOnlyMode();
  base::Time start, end;
  InitSparseCache(&start, &end);
  DoomEntriesBetween(start, end);
  EXPECT_EQ(3, cache_->GetEntryCount());

  start = end;
  end = base::Time::Now();
  DoomEntriesBetween(start, end);
  EXPECT_EQ(1, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DoomEntriesBetweenSparse) {
  base::Time start, end;
  InitSparseCache(&start, &end);
  DoomEntriesBetween(start, end);
  EXPECT_EQ(9, cache_->GetEntryCount());

  start = end;
  end = base::Time::Now();
  DoomEntriesBetween(start, end);
  EXPECT_EQ(3, cache_->GetEntryCount());
}

void DiskCacheBackendTest::BackendCalculateSizeOfAllEntries() {
  InitCache();

  // The cache is initially empty.
  EXPECT_EQ(0, CalculateSizeOfAllEntries());

  // Generate random entries and populate them with data of respective
  // sizes 0, 1, ..., count - 1 bytes.
  std::set<std::string> key_pool;
  CreateSetOfRandomEntries(&key_pool);

  int count = 0;
  for (std::string key : key_pool) {
    std::string data(count, ' ');
    scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(data);

    // Alternate between writing to first two streams to test that we do not
    // take only one stream into account.
    disk_cache::Entry* entry;
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    ASSERT_EQ(count, WriteData(entry, count % 2, 0, buffer.get(), count, true));
    entry->Close();

    ++count;
  }

  // The resulting size should be (0 + 1 + ... + count - 1) plus keys.
  int result = CalculateSizeOfAllEntries();
  int total_metadata_size = 0;
  for (std::string key : key_pool)
    total_metadata_size += GetEntryMetadataSize(key);
  EXPECT_EQ((count - 1) * count / 2 + total_metadata_size, result);

  // Add another entry and test if the size is updated. Then remove it and test
  // if the size is back to original value.
  {
    const int last_entry_size = 47;
    std::string data(last_entry_size, ' ');
    scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(data);

    disk_cache::Entry* entry;
    std::string key = GenerateKey(true);
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    ASSERT_EQ(last_entry_size,
              WriteData(entry, 0, 0, buffer.get(), last_entry_size, true));
    entry->Close();

    int new_result = CalculateSizeOfAllEntries();
    EXPECT_EQ(result + last_entry_size + GetEntryMetadataSize(key), new_result);

    DoomEntry(key);
    new_result = CalculateSizeOfAllEntries();
    EXPECT_EQ(result, new_result);
  }

  // After dooming the entries, the size should be back to zero.
  ASSERT_THAT(DoomAllEntries(), IsOk());
  EXPECT_EQ(0, CalculateSizeOfAllEntries());
}

TEST_F(DiskCacheBackendTest, CalculateSizeOfAllEntries) {
  BackendCalculateSizeOfAllEntries();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyCalculateSizeOfAllEntries) {
  SetMemoryOnlyMode();
  BackendCalculateSizeOfAllEntries();
}

TEST_F(DiskCacheBackendTest, SimpleCacheCalculateSizeOfAllEntries) {
  // Use net::APP_CACHE to make size estimations deterministic via
  // non-optimistic writes.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendCalculateSizeOfAllEntries();
}

void DiskCacheBackendTest::BackendCalculateSizeOfEntriesBetween() {
  InitCache();

  EXPECT_EQ(0, CalculateSizeOfEntriesBetween(base::Time(), base::Time::Max()));

  Time start = Time::Now();

  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("first", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time middle = Time::Now();
  AddDelay();

  ASSERT_THAT(CreateEntry("second", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("third_entry", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time end = Time::Now();

  int size_1 = GetEntryMetadataSize("first");
  int size_2 = GetEntryMetadataSize("second");
  int size_3 = GetEntryMetadataSize("third_entry");

  ASSERT_EQ(3, cache_->GetEntryCount());
  ASSERT_EQ(CalculateSizeOfAllEntries(),
            CalculateSizeOfEntriesBetween(base::Time(), base::Time::Max()));

  int start_end = CalculateSizeOfEntriesBetween(start, end);
  ASSERT_EQ(CalculateSizeOfAllEntries(), start_end);
  ASSERT_EQ(size_1 + size_2 + size_3, start_end);

  ASSERT_EQ(size_1, CalculateSizeOfEntriesBetween(start, middle));
  ASSERT_EQ(size_2 + size_3, CalculateSizeOfEntriesBetween(middle, end));

  // After dooming the entries, the size should be back to zero.
  ASSERT_THAT(DoomAllEntries(), IsOk());
  EXPECT_EQ(0, CalculateSizeOfEntriesBetween(base::Time(), base::Time::Max()));
}

TEST_F(DiskCacheBackendTest, CalculateSizeOfEntriesBetween) {
  InitCache();
  ASSERT_EQ(net::ERR_NOT_IMPLEMENTED,
            CalculateSizeOfEntriesBetween(base::Time(), base::Time::Max()));
}

TEST_F(DiskCacheBackendTest, MemoryOnlyCalculateSizeOfEntriesBetween) {
  SetMemoryOnlyMode();
  BackendCalculateSizeOfEntriesBetween();
}

TEST_F(DiskCacheBackendTest, SimpleCacheCalculateSizeOfEntriesBetween) {
  // Use net::APP_CACHE to make size estimations deterministic via
  // non-optimistic writes.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendCalculateSizeOfEntriesBetween();
}

void DiskCacheBackendTest::BackendTransaction(const std::string& name,
                                              int num_entries, bool load) {
  success_ = false;
  ASSERT_TRUE(CopyTestCache(name));
  DisableFirstCleanup();

  uint32_t mask;
  if (load) {
    mask = 0xf;
    SetMaxSize(0x100000);
  } else {
    // Clear the settings from the previous run.
    mask = 0;
    SetMaxSize(0);
  }
  SetMask(mask);

  InitCache();
  ASSERT_EQ(num_entries + 1, cache_->GetEntryCount());

  std::string key("the first key");
  disk_cache::Entry* entry1;
  ASSERT_NE(net::OK, OpenEntry(key, &entry1));

  int actual = cache_->GetEntryCount();
  if (num_entries != actual) {
    ASSERT_TRUE(load);
    // If there is a heavy load, inserting an entry will make another entry
    // dirty (on the hash bucket) so two entries are removed.
    ASSERT_EQ(num_entries - 1, actual);
  }

  cache_.reset();
  cache_impl_ = NULL;

  ASSERT_TRUE(CheckCacheIntegrity(cache_path_, new_eviction_, mask));
  success_ = true;
}

void DiskCacheBackendTest::BackendRecoverInsert() {
  // Tests with an empty cache.
  BackendTransaction("insert_empty1", 0, false);
  ASSERT_TRUE(success_) << "insert_empty1";
  BackendTransaction("insert_empty2", 0, false);
  ASSERT_TRUE(success_) << "insert_empty2";
  BackendTransaction("insert_empty3", 0, false);
  ASSERT_TRUE(success_) << "insert_empty3";

  // Tests with one entry on the cache.
  BackendTransaction("insert_one1", 1, false);
  ASSERT_TRUE(success_) << "insert_one1";
  BackendTransaction("insert_one2", 1, false);
  ASSERT_TRUE(success_) << "insert_one2";
  BackendTransaction("insert_one3", 1, false);
  ASSERT_TRUE(success_) << "insert_one3";

  // Tests with one hundred entries on the cache, tiny index.
  BackendTransaction("insert_load1", 100, true);
  ASSERT_TRUE(success_) << "insert_load1";
  BackendTransaction("insert_load2", 100, true);
  ASSERT_TRUE(success_) << "insert_load2";
}

TEST_F(DiskCacheBackendTest, RecoverInsert) {
  BackendRecoverInsert();
}

TEST_F(DiskCacheBackendTest, NewEvictionRecoverInsert) {
  SetNewEviction();
  BackendRecoverInsert();
}

void DiskCacheBackendTest::BackendRecoverRemove() {
  // Removing the only element.
  BackendTransaction("remove_one1", 0, false);
  ASSERT_TRUE(success_) << "remove_one1";
  BackendTransaction("remove_one2", 0, false);
  ASSERT_TRUE(success_) << "remove_one2";
  BackendTransaction("remove_one3", 0, false);
  ASSERT_TRUE(success_) << "remove_one3";

  // Removing the head.
  BackendTransaction("remove_head1", 1, false);
  ASSERT_TRUE(success_) << "remove_head1";
  BackendTransaction("remove_head2", 1, false);
  ASSERT_TRUE(success_) << "remove_head2";
  BackendTransaction("remove_head3", 1, false);
  ASSERT_TRUE(success_) << "remove_head3";

  // Removing the tail.
  BackendTransaction("remove_tail1", 1, false);
  ASSERT_TRUE(success_) << "remove_tail1";
  BackendTransaction("remove_tail2", 1, false);
  ASSERT_TRUE(success_) << "remove_tail2";
  BackendTransaction("remove_tail3", 1, false);
  ASSERT_TRUE(success_) << "remove_tail3";

  // Removing with one hundred entries on the cache, tiny index.
  BackendTransaction("remove_load1", 100, true);
  ASSERT_TRUE(success_) << "remove_load1";
  BackendTransaction("remove_load2", 100, true);
  ASSERT_TRUE(success_) << "remove_load2";
  BackendTransaction("remove_load3", 100, true);
  ASSERT_TRUE(success_) << "remove_load3";

  // This case cannot be reverted.
  BackendTransaction("remove_one4", 0, false);
  ASSERT_TRUE(success_) << "remove_one4";
  BackendTransaction("remove_head4", 1, false);
  ASSERT_TRUE(success_) << "remove_head4";
}

#if defined(OS_WIN)
// http://crbug.com/396392
#define MAYBE_RecoverRemove DISABLED_RecoverRemove
#else
#define MAYBE_RecoverRemove RecoverRemove
#endif
TEST_F(DiskCacheBackendTest, MAYBE_RecoverRemove) {
  BackendRecoverRemove();
}

#if defined(OS_WIN)
// http://crbug.com/396392
#define MAYBE_NewEvictionRecoverRemove DISABLED_NewEvictionRecoverRemove
#else
#define MAYBE_NewEvictionRecoverRemove NewEvictionRecoverRemove
#endif
TEST_F(DiskCacheBackendTest, MAYBE_NewEvictionRecoverRemove) {
  SetNewEviction();
  BackendRecoverRemove();
}

void DiskCacheBackendTest::BackendRecoverWithEviction() {
  success_ = false;
  ASSERT_TRUE(CopyTestCache("insert_load1"));
  DisableFirstCleanup();

  SetMask(0xf);
  SetMaxSize(0x1000);

  // We should not crash here.
  InitCache();
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, RecoverWithEviction) {
  BackendRecoverWithEviction();
}

TEST_F(DiskCacheBackendTest, NewEvictionRecoverWithEviction) {
  SetNewEviction();
  BackendRecoverWithEviction();
}

// Tests that the |BackendImpl| fails to start with the wrong cache version.
TEST_F(DiskCacheTest, WrongVersion) {
  ASSERT_TRUE(CopyTestCache("wrong_version"));
  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
      base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));
  net::TestCompletionCallback cb;

  std::unique_ptr<disk_cache::BackendImpl> cache(new disk_cache::BackendImpl(
      cache_path_, cache_thread.task_runner(), NULL));
  int rv = cache->Init(cb.callback());
  ASSERT_THAT(cb.GetResult(rv), IsError(net::ERR_FAILED));
}

// Tests that the disk cache successfully joins the control group, dropping the
// existing cache in favour of a new empty cache.
// Disabled on android since this test requires cache creator to create
// blockfile caches.
#if !defined(OS_ANDROID)
TEST_F(DiskCacheTest, SimpleCacheControlJoin) {
  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
                  base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));

  std::unique_ptr<disk_cache::BackendImpl> cache =
      CreateExistingEntryCache(cache_thread, cache_path_);
  ASSERT_TRUE(cache.get());
  cache.reset();

  // Instantiate the SimpleCacheTrial, forcing this run into the
  // ExperimentControl group.
  base::FieldTrialList field_trial_list(
      base::MakeUnique<base::MockEntropyProvider>());
  base::FieldTrialList::CreateFieldTrial("SimpleCacheTrial",
                                         "ExperimentControl");
  net::TestCompletionCallback cb;
  std::unique_ptr<disk_cache::Backend> base_cache;
  int rv = disk_cache::CreateCacheBackend(net::DISK_CACHE,
                                          net::CACHE_BACKEND_BLOCKFILE,
                                          cache_path_,
                                          0,
                                          true,
                                          cache_thread.task_runner(),
                                          NULL,
                                          &base_cache,
                                          cb.callback());
  ASSERT_THAT(cb.GetResult(rv), IsOk());
  EXPECT_EQ(0, base_cache->GetEntryCount());
}
#endif

// Tests that the disk cache can restart in the control group preserving
// existing entries.
TEST_F(DiskCacheTest, SimpleCacheControlRestart) {
  // Instantiate the SimpleCacheTrial, forcing this run into the
  // ExperimentControl group.
  base::FieldTrialList field_trial_list(
      base::MakeUnique<base::MockEntropyProvider>());
  base::FieldTrialList::CreateFieldTrial("SimpleCacheTrial",
                                         "ExperimentControl");

  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
                  base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));

  std::unique_ptr<disk_cache::BackendImpl> cache =
      CreateExistingEntryCache(cache_thread, cache_path_);
  ASSERT_TRUE(cache.get());

  net::TestCompletionCallback cb;

  const int kRestartCount = 5;
  for (int i = 0; i < kRestartCount; ++i) {
    cache.reset(new disk_cache::BackendImpl(cache_path_,
                                            cache_thread.task_runner(), NULL));
    int rv = cache->Init(cb.callback());
    ASSERT_THAT(cb.GetResult(rv), IsOk());
    EXPECT_EQ(1, cache->GetEntryCount());

    disk_cache::Entry* entry = NULL;
    rv = cache->OpenEntry(kExistingEntryKey, &entry, cb.callback());
    ASSERT_THAT(cb.GetResult(rv), IsOk());
    EXPECT_NE(nullptr, entry);
    entry->Close();
  }
}

// Tests that the disk cache can leave the control group preserving existing
// entries.
TEST_F(DiskCacheTest, SimpleCacheControlLeave) {
  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
      base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));

  {
    // Instantiate the SimpleCacheTrial, forcing this run into the
    // ExperimentControl group.
    base::FieldTrialList field_trial_list(
        base::MakeUnique<base::MockEntropyProvider>());
    base::FieldTrialList::CreateFieldTrial("SimpleCacheTrial",
                                           "ExperimentControl");

    std::unique_ptr<disk_cache::BackendImpl> cache =
        CreateExistingEntryCache(cache_thread, cache_path_);
    ASSERT_TRUE(cache.get());
  }

  // Instantiate the SimpleCacheTrial, forcing this run into the
  // ExperimentNo group.
  base::FieldTrialList field_trial_list(
      base::MakeUnique<base::MockEntropyProvider>());
  base::FieldTrialList::CreateFieldTrial("SimpleCacheTrial", "ExperimentNo");
  net::TestCompletionCallback cb;

  const int kRestartCount = 5;
  for (int i = 0; i < kRestartCount; ++i) {
    std::unique_ptr<disk_cache::BackendImpl> cache(new disk_cache::BackendImpl(
        cache_path_, cache_thread.task_runner(), NULL));
    int rv = cache->Init(cb.callback());
    ASSERT_THAT(cb.GetResult(rv), IsOk());
    EXPECT_EQ(1, cache->GetEntryCount());

    disk_cache::Entry* entry = NULL;
    rv = cache->OpenEntry(kExistingEntryKey, &entry, cb.callback());
    ASSERT_THAT(cb.GetResult(rv), IsOk());
    EXPECT_NE(nullptr, entry);
    entry->Close();
  }
}

// Tests that the cache is properly restarted on recovery error.
// Disabled on android since this test requires cache creator to create
// blockfile caches.
#if !defined(OS_ANDROID)
TEST_F(DiskCacheBackendTest, DeleteOld) {
  ASSERT_TRUE(CopyTestCache("wrong_version"));
  SetNewEviction();
  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
      base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));

  net::TestCompletionCallback cb;
  bool prev = base::ThreadRestrictions::SetIOAllowed(false);
  base::FilePath path(cache_path_);
  int rv = disk_cache::CreateCacheBackend(net::DISK_CACHE,
                                          net::CACHE_BACKEND_BLOCKFILE,
                                          path,
                                          0,
                                          true,
                                          cache_thread.task_runner(),
                                          NULL,
                                          &cache_,
                                          cb.callback());
  path.clear();  // Make sure path was captured by the previous call.
  ASSERT_THAT(cb.GetResult(rv), IsOk());
  base::ThreadRestrictions::SetIOAllowed(prev);
  cache_.reset();
  EXPECT_TRUE(CheckCacheIntegrity(cache_path_, new_eviction_, mask_));
}
#endif

// We want to be able to deal with messed up entries on disk.
void DiskCacheBackendTest::BackendInvalidEntry2() {
  ASSERT_TRUE(CopyTestCache("bad_entry"));
  DisableFirstCleanup();
  InitCache();

  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(OpenEntry("the first key", &entry1), IsOk());
  EXPECT_NE(net::OK, OpenEntry("some other key", &entry2));
  entry1->Close();

  // CheckCacheIntegrity will fail at this point.
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, InvalidEntry2) {
  BackendInvalidEntry2();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry2) {
  SetNewEviction();
  BackendInvalidEntry2();
}

// Tests that we don't crash or hang when enumerating this cache.
void DiskCacheBackendTest::BackendInvalidEntry3() {
  SetMask(0x1);  // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  disk_cache::Entry* entry;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  while (iter->OpenNextEntry(&entry) == net::OK) {
    entry->Close();
  }
}

TEST_F(DiskCacheBackendTest, InvalidEntry3) {
  ASSERT_TRUE(CopyTestCache("dirty_entry3"));
  BackendInvalidEntry3();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry3) {
  ASSERT_TRUE(CopyTestCache("dirty_entry4"));
  SetNewEviction();
  BackendInvalidEntry3();
  DisableIntegrityCheck();
}

// Test that we handle a dirty entry on the LRU list, already replaced with
// the same key, and with hash collisions.
TEST_F(DiskCacheBackendTest, InvalidEntry4) {
  ASSERT_TRUE(CopyTestCache("dirty_entry3"));
  SetMask(0x1);  // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  TrimForTest(false);
}

// Test that we handle a dirty entry on the deleted list, already replaced with
// the same key, and with hash collisions.
TEST_F(DiskCacheBackendTest, InvalidEntry5) {
  ASSERT_TRUE(CopyTestCache("dirty_entry4"));
  SetNewEviction();
  SetMask(0x1);  // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  TrimDeletedListForTest(false);
}

TEST_F(DiskCacheBackendTest, InvalidEntry6) {
  ASSERT_TRUE(CopyTestCache("dirty_entry5"));
  SetMask(0x1);  // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  // There is a dirty entry (but marked as clean) at the end, pointing to a
  // deleted entry through the hash collision list. We should not re-insert the
  // deleted entry into the index table.

  TrimForTest(false);
  // The cache should be clean (as detected by CheckCacheIntegrity).
}

// Tests that we don't hang when there is a loop on the hash collision list.
// The test cache could be a result of bug 69135.
TEST_F(DiskCacheBackendTest, BadNextEntry1) {
  ASSERT_TRUE(CopyTestCache("list_loop2"));
  SetMask(0x1);  // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  // The second entry points at itselft, and the first entry is not accessible
  // though the index, but it is at the head of the LRU.

  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("The first key", &entry), IsOk());
  entry->Close();

  TrimForTest(false);
  TrimForTest(false);
  ASSERT_THAT(OpenEntry("The first key", &entry), IsOk());
  entry->Close();
  EXPECT_EQ(1, cache_->GetEntryCount());
}

// Tests that we don't hang when there is a loop on the hash collision list.
// The test cache could be a result of bug 69135.
TEST_F(DiskCacheBackendTest, BadNextEntry2) {
  ASSERT_TRUE(CopyTestCache("list_loop3"));
  SetMask(0x1);  // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  // There is a wide loop of 5 entries.

  disk_cache::Entry* entry;
  ASSERT_NE(net::OK, OpenEntry("Not present key", &entry));
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry6) {
  ASSERT_TRUE(CopyTestCache("bad_rankings3"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();

  // The second entry is dirty, but removing it should not corrupt the list.
  disk_cache::Entry* entry;
  ASSERT_NE(net::OK, OpenEntry("the second key", &entry));
  ASSERT_THAT(OpenEntry("the first key", &entry), IsOk());

  // This should not delete the cache.
  entry->Doom();
  FlushQueueForTest();
  entry->Close();

  ASSERT_THAT(OpenEntry("some other key", &entry), IsOk());
  entry->Close();
}

// Tests handling of corrupt entries by keeping the rankings node around, with
// a fatal failure.
void DiskCacheBackendTest::BackendInvalidEntry7() {
  const int kSize = 0x3000;  // 12 kB.
  SetMaxSize(kSize * 10);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->rankings()->Data()->next = 0;
  entry_impl->rankings()->Store();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(2, cache_->GetEntryCount());

  // This should detect the bad entry.
  EXPECT_NE(net::OK, OpenEntry(second, &entry));
  EXPECT_EQ(1, cache_->GetEntryCount());

  // We should delete the cache. The list still has a corrupt node.
  std::unique_ptr<TestIterator> iter = CreateIterator();
  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, InvalidEntry7) {
  BackendInvalidEntry7();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry7) {
  SetNewEviction();
  BackendInvalidEntry7();
}

// Tests handling of corrupt entries by keeping the rankings node around, with
// a non fatal failure.
void DiskCacheBackendTest::BackendInvalidEntry8() {
  const int kSize = 0x3000;  // 12 kB
  SetMaxSize(kSize * 10);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->rankings()->Data()->contents = 0;
  entry_impl->rankings()->Store();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(2, cache_->GetEntryCount());

  // This should detect the bad entry.
  EXPECT_NE(net::OK, OpenEntry(second, &entry));
  EXPECT_EQ(1, cache_->GetEntryCount());

  // We should not delete the cache.
  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
  entry->Close();
  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));
  EXPECT_EQ(1, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, InvalidEntry8) {
  BackendInvalidEntry8();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry8) {
  SetNewEviction();
  BackendInvalidEntry8();
}

// Tests handling of corrupt entries detected by enumerations. Note that these
// tests (xx9 to xx11) are basically just going though slightly different
// codepaths so they are tighlty coupled with the code, but that is better than
// not testing error handling code.
void DiskCacheBackendTest::BackendInvalidEntry9(bool eviction) {
  const int kSize = 0x3000;  // 12 kB.
  SetMaxSize(kSize * 10);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->entry()->Data()->state = 0xbad;
  entry_impl->entry()->Store();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(2, cache_->GetEntryCount());

  if (eviction) {
    TrimForTest(false);
    EXPECT_EQ(1, cache_->GetEntryCount());
    TrimForTest(false);
    EXPECT_EQ(1, cache_->GetEntryCount());
  } else {
    // We should detect the problem through the list, but we should not delete
    // the entry, just fail the iteration.
    std::unique_ptr<TestIterator> iter = CreateIterator();
    EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));

    // Now a full iteration will work, and return one entry.
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    entry->Close();
    EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));

    // This should detect what's left of the bad entry.
    EXPECT_NE(net::OK, OpenEntry(second, &entry));
    EXPECT_EQ(2, cache_->GetEntryCount());
  }
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, InvalidEntry9) {
  BackendInvalidEntry9(false);
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry9) {
  SetNewEviction();
  BackendInvalidEntry9(false);
}

TEST_F(DiskCacheBackendTest, TrimInvalidEntry9) {
  BackendInvalidEntry9(true);
}

TEST_F(DiskCacheBackendTest, NewEvictionTrimInvalidEntry9) {
  SetNewEviction();
  BackendInvalidEntry9(true);
}

// Tests handling of corrupt entries detected by enumerations.
void DiskCacheBackendTest::BackendInvalidEntry10(bool eviction) {
  const int kSize = 0x3000;  // 12 kB.
  SetMaxSize(kSize * 10);
  SetNewEviction();
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(OpenEntry(first, &entry), IsOk());
  EXPECT_EQ(0, WriteData(entry, 0, 200, NULL, 0, false));
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->entry()->Data()->state = 0xbad;
  entry_impl->entry()->Store();
  entry->Close();
  ASSERT_THAT(CreateEntry("third", &entry), IsOk());
  entry->Close();
  EXPECT_EQ(3, cache_->GetEntryCount());

  // We have:
  // List 0: third -> second (bad).
  // List 1: first.

  if (eviction) {
    // Detection order: second -> first -> third.
    TrimForTest(false);
    EXPECT_EQ(3, cache_->GetEntryCount());
    TrimForTest(false);
    EXPECT_EQ(2, cache_->GetEntryCount());
    TrimForTest(false);
    EXPECT_EQ(1, cache_->GetEntryCount());
  } else {
    // Detection order: third -> second -> first.
    // We should detect the problem through the list, but we should not delete
    // the entry.
    std::unique_ptr<TestIterator> iter = CreateIterator();
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    entry->Close();
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    EXPECT_EQ(first, entry->GetKey());
    entry->Close();
    EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));
  }
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, InvalidEntry10) {
  BackendInvalidEntry10(false);
}

TEST_F(DiskCacheBackendTest, TrimInvalidEntry10) {
  BackendInvalidEntry10(true);
}

// Tests handling of corrupt entries detected by enumerations.
void DiskCacheBackendTest::BackendInvalidEntry11(bool eviction) {
  const int kSize = 0x3000;  // 12 kB.
  SetMaxSize(kSize * 10);
  SetNewEviction();
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(OpenEntry(first, &entry), IsOk());
  EXPECT_EQ(0, WriteData(entry, 0, 200, NULL, 0, false));
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(OpenEntry(second, &entry), IsOk());
  EXPECT_EQ(0, WriteData(entry, 0, 200, NULL, 0, false));

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->entry()->Data()->state = 0xbad;
  entry_impl->entry()->Store();
  entry->Close();
  ASSERT_THAT(CreateEntry("third", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(3, cache_->GetEntryCount());

  // We have:
  // List 0: third.
  // List 1: second (bad) -> first.

  if (eviction) {
    // Detection order: third -> first -> second.
    TrimForTest(false);
    EXPECT_EQ(2, cache_->GetEntryCount());
    TrimForTest(false);
    EXPECT_EQ(1, cache_->GetEntryCount());
    TrimForTest(false);
    EXPECT_EQ(1, cache_->GetEntryCount());
  } else {
    // Detection order: third -> second.
    // We should detect the problem through the list, but we should not delete
    // the entry, just fail the iteration.
    std::unique_ptr<TestIterator> iter = CreateIterator();
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    entry->Close();
    EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));

    // Now a full iteration will work, and return two entries.
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    entry->Close();
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    entry->Close();
    EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));
  }
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, InvalidEntry11) {
  BackendInvalidEntry11(false);
}

TEST_F(DiskCacheBackendTest, TrimInvalidEntry11) {
  BackendInvalidEntry11(true);
}

// Tests handling of corrupt entries in the middle of a long eviction run.
void DiskCacheBackendTest::BackendTrimInvalidEntry12() {
  const int kSize = 0x3000;  // 12 kB
  SetMaxSize(kSize * 10);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->entry()->Data()->state = 0xbad;
  entry_impl->entry()->Store();
  entry->Close();
  ASSERT_THAT(CreateEntry("third", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("fourth", &entry), IsOk());
  TrimForTest(true);
  EXPECT_EQ(1, cache_->GetEntryCount());
  entry->Close();
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, TrimInvalidEntry12) {
  BackendTrimInvalidEntry12();
}

TEST_F(DiskCacheBackendTest, NewEvictionTrimInvalidEntry12) {
  SetNewEviction();
  BackendTrimInvalidEntry12();
}

// We want to be able to deal with messed up entries on disk.
void DiskCacheBackendTest::BackendInvalidRankings2() {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();

  disk_cache::Entry *entry1, *entry2;
  EXPECT_NE(net::OK, OpenEntry("the first key", &entry1));
  ASSERT_THAT(OpenEntry("some other key", &entry2), IsOk());
  entry2->Close();

  // CheckCacheIntegrity will fail at this point.
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, InvalidRankings2) {
  BackendInvalidRankings2();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidRankings2) {
  SetNewEviction();
  BackendInvalidRankings2();
}

// If the LRU is corrupt, we delete the cache.
void DiskCacheBackendTest::BackendInvalidRankings() {
  disk_cache::Entry* entry;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
  entry->Close();
  EXPECT_EQ(2, cache_->GetEntryCount());

  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));
  FlushQueueForTest();  // Allow the restart to finish.
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, InvalidRankingsSuccess) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();
  BackendInvalidRankings();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidRankingsSuccess) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  BackendInvalidRankings();
}

TEST_F(DiskCacheBackendTest, InvalidRankingsFailure) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendInvalidRankings();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidRankingsFailure) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendInvalidRankings();
}

// If the LRU is corrupt and we have open entries, we disable the cache.
void DiskCacheBackendTest::BackendDisable() {
  disk_cache::Entry *entry1, *entry2;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry1), IsOk());

  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry2));
  EXPECT_EQ(0, cache_->GetEntryCount());
  EXPECT_NE(net::OK, CreateEntry("Something new", &entry2));

  entry1->Close();
  FlushQueueForTest();  // Flushing the Close posts a task to restart the cache.
  FlushQueueForTest();  // This one actually allows that task to complete.

  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DisableSuccess) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();
  BackendDisable();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableSuccess) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  BackendDisable();
}

TEST_F(DiskCacheBackendTest, DisableFailure) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendDisable();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableFailure) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendDisable();
}

// This is another type of corruption on the LRU; disable the cache.
void DiskCacheBackendTest::BackendDisable2() {
  EXPECT_EQ(8, cache_->GetEntryCount());

  disk_cache::Entry* entry;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  int count = 0;
  while (iter->OpenNextEntry(&entry) == net::OK) {
    ASSERT_TRUE(NULL != entry);
    entry->Close();
    count++;
    ASSERT_LT(count, 9);
  };

  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DisableSuccess2) {
  ASSERT_TRUE(CopyTestCache("list_loop"));
  DisableFirstCleanup();
  InitCache();
  BackendDisable2();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableSuccess2) {
  ASSERT_TRUE(CopyTestCache("list_loop"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  BackendDisable2();
}

TEST_F(DiskCacheBackendTest, DisableFailure2) {
  ASSERT_TRUE(CopyTestCache("list_loop"));
  DisableFirstCleanup();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendDisable2();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableFailure2) {
  ASSERT_TRUE(CopyTestCache("list_loop"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendDisable2();
}

// If the index size changes when we disable the cache, we should not crash.
void DiskCacheBackendTest::BackendDisable3() {
  disk_cache::Entry *entry1, *entry2;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  EXPECT_EQ(2, cache_->GetEntryCount());
  ASSERT_THAT(iter->OpenNextEntry(&entry1), IsOk());
  entry1->Close();

  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry2));
  FlushQueueForTest();

  ASSERT_THAT(CreateEntry("Something new", &entry2), IsOk());
  entry2->Close();

  EXPECT_EQ(1, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DisableSuccess3) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  SetMaxSize(20 * 1024 * 1024);
  InitCache();
  BackendDisable3();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableSuccess3) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  SetMaxSize(20 * 1024 * 1024);
  SetNewEviction();
  InitCache();
  BackendDisable3();
}

// If we disable the cache, already open entries should work as far as possible.
void DiskCacheBackendTest::BackendDisable4() {
  disk_cache::Entry *entry1, *entry2, *entry3, *entry4;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry1), IsOk());

  char key2[2000];
  char key3[20000];
  CacheTestFillBuffer(key2, sizeof(key2), true);
  CacheTestFillBuffer(key3, sizeof(key3), true);
  key2[sizeof(key2) - 1] = '\0';
  key3[sizeof(key3) - 1] = '\0';
  ASSERT_THAT(CreateEntry(key2, &entry2), IsOk());
  ASSERT_THAT(CreateEntry(key3, &entry3), IsOk());

  const int kBufSize = 20000;
  scoped_refptr<net::IOBuffer> buf(new net::IOBuffer(kBufSize));
  memset(buf->data(), 0, kBufSize);
  EXPECT_EQ(100, WriteData(entry2, 0, 0, buf.get(), 100, false));
  EXPECT_EQ(kBufSize, WriteData(entry3, 0, 0, buf.get(), kBufSize, false));

  // This line should disable the cache but not delete it.
  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry4));
  EXPECT_EQ(0, cache_->GetEntryCount());

  EXPECT_NE(net::OK, CreateEntry("cache is disabled", &entry4));

  EXPECT_EQ(100, ReadData(entry2, 0, 0, buf.get(), 100));
  EXPECT_EQ(100, WriteData(entry2, 0, 0, buf.get(), 100, false));
  EXPECT_EQ(100, WriteData(entry2, 1, 0, buf.get(), 100, false));

  EXPECT_EQ(kBufSize, ReadData(entry3, 0, 0, buf.get(), kBufSize));
  EXPECT_EQ(kBufSize, WriteData(entry3, 0, 0, buf.get(), kBufSize, false));
  EXPECT_EQ(kBufSize, WriteData(entry3, 1, 0, buf.get(), kBufSize, false));

  std::string key = entry2->GetKey();
  EXPECT_EQ(sizeof(key2) - 1, key.size());
  key = entry3->GetKey();
  EXPECT_EQ(sizeof(key3) - 1, key.size());

  entry1->Close();
  entry2->Close();
  entry3->Close();
  FlushQueueForTest();  // Flushing the Close posts a task to restart the cache.
  FlushQueueForTest();  // This one actually allows that task to complete.

  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DisableSuccess4) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();
  BackendDisable4();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableSuccess4) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  BackendDisable4();
}

// Tests the exposed API with a disabled cache.
void DiskCacheBackendTest::BackendDisabledAPI() {
  cache_impl_->SetUnitTestMode();  // Simulate failure restarting the cache.

  disk_cache::Entry* entry1, *entry2;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  EXPECT_EQ(2, cache_->GetEntryCount());
  ASSERT_THAT(iter->OpenNextEntry(&entry1), IsOk());
  entry1->Close();
  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry2));
  FlushQueueForTest();
  // The cache should be disabled.

  EXPECT_EQ(net::DISK_CACHE, cache_->GetCacheType());
  EXPECT_EQ(0, cache_->GetEntryCount());
  EXPECT_NE(net::OK, OpenEntry("First", &entry2));
  EXPECT_NE(net::OK, CreateEntry("Something new", &entry2));
  EXPECT_NE(net::OK, DoomEntry("First"));
  EXPECT_NE(net::OK, DoomAllEntries());
  EXPECT_NE(net::OK, DoomEntriesBetween(Time(), Time::Now()));
  EXPECT_NE(net::OK, DoomEntriesSince(Time()));
  iter = CreateIterator();
  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry2));

  base::StringPairs stats;
  cache_->GetStats(&stats);
  EXPECT_TRUE(stats.empty());
  cache_->OnExternalCacheHit("First");
}

TEST_F(DiskCacheBackendTest, DisabledAPI) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  InitCache();
  BackendDisabledAPI();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisabledAPI) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  BackendDisabledAPI();
}

// Test that some eviction of some kind happens.
void DiskCacheBackendTest::BackendEviction() {
  const int kMaxSize = 200 * 1024;
  const int kMaxEntryCount = 20;
  const int kWriteSize = kMaxSize / kMaxEntryCount;

  const int kWriteEntryCount = kMaxEntryCount * 2;

  static_assert(kWriteEntryCount * kWriteSize > kMaxSize,
                "must write more than MaxSize");

  SetMaxSize(kMaxSize);
  InitSparseCache(nullptr, nullptr);

  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kWriteSize));
  CacheTestFillBuffer(buffer->data(), kWriteSize, false);

  std::string key_prefix("prefix");
  for (int i = 0; i < kWriteEntryCount; ++i) {
    AddDelay();
    disk_cache::Entry* entry = NULL;
    ASSERT_THAT(CreateEntry(key_prefix + base::IntToString(i), &entry), IsOk());
    disk_cache::ScopedEntryPtr entry_closer(entry);
    EXPECT_EQ(kWriteSize,
              WriteData(entry, 1, 0, buffer.get(), kWriteSize, false));
  }

  int size = CalculateSizeOfAllEntries();
  EXPECT_GT(kMaxSize, size);
}

TEST_F(DiskCacheBackendTest, BackendEviction) {
  BackendEviction();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyBackendEviction) {
  SetMemoryOnlyMode();
  BackendEviction();
}

// TODO(gavinp): Enable BackendEviction test for simple cache after performance
// problems are addressed. See crbug.com/588184 for more information.

// This overly specific looking test is a regression test aimed at
// crbug.com/589186.
TEST_F(DiskCacheBackendTest, MemoryOnlyUseAfterFree) {
  SetMemoryOnlyMode();

  const int kMaxSize = 200 * 1024;
  const int kMaxEntryCount = 20;
  const int kWriteSize = kMaxSize / kMaxEntryCount;

  SetMaxSize(kMaxSize);
  InitCache();

  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kWriteSize));
  CacheTestFillBuffer(buffer->data(), kWriteSize, false);

  // Create an entry to be our sparse entry that gets written later.
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("first parent", &entry), IsOk());
  disk_cache::ScopedEntryPtr first_parent(entry);

  // Create a ton of entries, and keep them open, to put the cache well above
  // its eviction threshhold.
  const int kTooManyEntriesCount = kMaxEntryCount * 2;
  std::list<disk_cache::ScopedEntryPtr> open_entries;
  std::string key_prefix("prefix");
  for (int i = 0; i < kTooManyEntriesCount; ++i) {
    ASSERT_THAT(CreateEntry(key_prefix + base::IntToString(i), &entry), IsOk());
    EXPECT_EQ(kWriteSize,
              WriteData(entry, 1, 0, buffer.get(), kWriteSize, false));
    open_entries.push_back(disk_cache::ScopedEntryPtr(entry));
  }
  EXPECT_LT(kMaxSize, CalculateSizeOfAllEntries());

  // Writing this sparse data should not crash.
  EXPECT_EQ(1024, first_parent->WriteSparseData(32768, buffer.get(), 1024,
                                                net::CompletionCallback()));
}

TEST_F(DiskCacheTest, Backend_UsageStatsTimer) {
  MessageLoopHelper helper;

  ASSERT_TRUE(CleanupCacheDir());
  std::unique_ptr<disk_cache::BackendImpl> cache;
  cache.reset(new disk_cache::BackendImpl(
      cache_path_, base::ThreadTaskRunnerHandle::Get(), NULL));
  ASSERT_TRUE(NULL != cache.get());
  cache->SetUnitTestMode();
  ASSERT_THAT(cache->SyncInit(), IsOk());

  // Wait for a callback that never comes... about 2 secs :). The message loop
  // has to run to allow invocation of the usage timer.
  helper.WaitUntilCacheIoFinished(1);
}

TEST_F(DiskCacheBackendTest, TimerNotCreated) {
  ASSERT_TRUE(CopyTestCache("wrong_version"));

  std::unique_ptr<disk_cache::BackendImpl> cache;
  cache.reset(new disk_cache::BackendImpl(
      cache_path_, base::ThreadTaskRunnerHandle::Get(), NULL));
  ASSERT_TRUE(NULL != cache.get());
  cache->SetUnitTestMode();
  ASSERT_NE(net::OK, cache->SyncInit());

  ASSERT_TRUE(NULL == cache->GetTimerForTest());

  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, Backend_UsageStats) {
  InitCache();
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("key", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  disk_cache::StatsItems stats;
  cache_->GetStats(&stats);
  EXPECT_FALSE(stats.empty());

  disk_cache::StatsItems::value_type hits("Create hit", "0x1");
  EXPECT_EQ(1, std::count(stats.begin(), stats.end(), hits));

  cache_.reset();

  // Now open the cache and verify that the stats are still there.
  DisableFirstCleanup();
  InitCache();
  EXPECT_EQ(1, cache_->GetEntryCount());

  stats.clear();
  cache_->GetStats(&stats);
  EXPECT_FALSE(stats.empty());

  EXPECT_EQ(1, std::count(stats.begin(), stats.end(), hits));
}

void DiskCacheBackendTest::BackendDoomAll() {
  InitCache();

  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(CreateEntry("first", &entry1), IsOk());
  ASSERT_THAT(CreateEntry("second", &entry2), IsOk());
  entry1->Close();
  entry2->Close();

  ASSERT_THAT(CreateEntry("third", &entry1), IsOk());
  ASSERT_THAT(CreateEntry("fourth", &entry2), IsOk());

  ASSERT_EQ(4, cache_->GetEntryCount());
  EXPECT_THAT(DoomAllEntries(), IsOk());
  ASSERT_EQ(0, cache_->GetEntryCount());

  // We should stop posting tasks at some point (if we post any).
  base::RunLoop().RunUntilIdle();

  disk_cache::Entry *entry3, *entry4;
  EXPECT_NE(net::OK, OpenEntry("third", &entry3));
  ASSERT_THAT(CreateEntry("third", &entry3), IsOk());
  ASSERT_THAT(CreateEntry("fourth", &entry4), IsOk());

  EXPECT_THAT(DoomAllEntries(), IsOk());
  ASSERT_EQ(0, cache_->GetEntryCount());

  entry1->Close();
  entry2->Close();
  entry3->Doom();  // The entry should be already doomed, but this must work.
  entry3->Close();
  entry4->Close();

  // Now try with all references released.
  ASSERT_THAT(CreateEntry("third", &entry1), IsOk());
  ASSERT_THAT(CreateEntry("fourth", &entry2), IsOk());
  entry1->Close();
  entry2->Close();

  ASSERT_EQ(2, cache_->GetEntryCount());
  EXPECT_THAT(DoomAllEntries(), IsOk());
  ASSERT_EQ(0, cache_->GetEntryCount());

  EXPECT_THAT(DoomAllEntries(), IsOk());
}

TEST_F(DiskCacheBackendTest, DoomAll) {
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, NewEvictionDoomAll) {
  SetNewEviction();
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomAll) {
  SetMemoryOnlyMode();
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, AppCacheOnlyDoomAll) {
  SetCacheType(net::APP_CACHE);
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, ShaderCacheOnlyDoomAll) {
  SetCacheType(net::SHADER_CACHE);
  BackendDoomAll();
}

// If the index size changes when we doom the cache, we should not crash.
void DiskCacheBackendTest::BackendDoomAll2() {
  EXPECT_EQ(2, cache_->GetEntryCount());
  EXPECT_THAT(DoomAllEntries(), IsOk());

  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("Something new", &entry), IsOk());
  entry->Close();

  EXPECT_EQ(1, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DoomAll2) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  SetMaxSize(20 * 1024 * 1024);
  InitCache();
  BackendDoomAll2();
}

TEST_F(DiskCacheBackendTest, NewEvictionDoomAll2) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  SetMaxSize(20 * 1024 * 1024);
  SetNewEviction();
  InitCache();
  BackendDoomAll2();
}

// We should be able to create the same entry on multiple simultaneous instances
// of the cache.
TEST_F(DiskCacheTest, MultipleInstances) {
  base::ScopedTempDir store1, store2;
  ASSERT_TRUE(store1.CreateUniqueTempDir());
  ASSERT_TRUE(store2.CreateUniqueTempDir());

  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
      base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));
  net::TestCompletionCallback cb;

  const int kNumberOfCaches = 2;
  std::unique_ptr<disk_cache::Backend> cache[kNumberOfCaches];

  int rv = disk_cache::CreateCacheBackend(
      net::DISK_CACHE, net::CACHE_BACKEND_DEFAULT, store1.GetPath(), 0, false,
      cache_thread.task_runner(), NULL, &cache[0], cb.callback());
  ASSERT_THAT(cb.GetResult(rv), IsOk());
  rv = disk_cache::CreateCacheBackend(
      net::MEDIA_CACHE, net::CACHE_BACKEND_DEFAULT, store2.GetPath(), 0, false,
      cache_thread.task_runner(), NULL, &cache[1], cb.callback());
  ASSERT_THAT(cb.GetResult(rv), IsOk());

  ASSERT_TRUE(cache[0].get() != NULL && cache[1].get() != NULL);

  std::string key("the first key");
  disk_cache::Entry* entry;
  for (int i = 0; i < kNumberOfCaches; i++) {
    rv = cache[i]->CreateEntry(key, &entry, cb.callback());
    ASSERT_THAT(cb.GetResult(rv), IsOk());
    entry->Close();
  }
}

// Test the six regions of the curve that determines the max cache size.
TEST_F(DiskCacheTest, AutomaticMaxSize) {
  using disk_cache::kDefaultCacheSize;
  int64_t large_size = kDefaultCacheSize;

  // Region 1: expected = available * 0.8
  EXPECT_EQ((kDefaultCacheSize - 1) * 8 / 10,
            disk_cache::PreferredCacheSize(large_size - 1));
  EXPECT_EQ(kDefaultCacheSize * 8 / 10,
            disk_cache::PreferredCacheSize(large_size));
  EXPECT_EQ(kDefaultCacheSize - 1,
            disk_cache::PreferredCacheSize(large_size * 10 / 8 - 1));

  // Region 2: expected = default_size
  EXPECT_EQ(kDefaultCacheSize,
            disk_cache::PreferredCacheSize(large_size * 10 / 8));
  EXPECT_EQ(kDefaultCacheSize,
            disk_cache::PreferredCacheSize(large_size * 10 - 1));

  // Region 3: expected = available * 0.1
  EXPECT_EQ(kDefaultCacheSize,
            disk_cache::PreferredCacheSize(large_size * 10));
  EXPECT_EQ((kDefaultCacheSize * 25 - 1) / 10,
            disk_cache::PreferredCacheSize(large_size * 25 - 1));

  // Region 4: expected = default_size * 2.5
  EXPECT_EQ(kDefaultCacheSize * 25 / 10,
            disk_cache::PreferredCacheSize(large_size * 25));
  EXPECT_EQ(kDefaultCacheSize * 25 / 10,
            disk_cache::PreferredCacheSize(large_size * 100 - 1));
  EXPECT_EQ(kDefaultCacheSize * 25 / 10,
            disk_cache::PreferredCacheSize(large_size * 100));
  EXPECT_EQ(kDefaultCacheSize * 25 / 10,
            disk_cache::PreferredCacheSize(large_size * 250 - 1));

  // Region 5: expected = available * 0.1
  int64_t largest_size = kDefaultCacheSize * 4;
  EXPECT_EQ(kDefaultCacheSize * 25 / 10,
            disk_cache::PreferredCacheSize(large_size * 250));
  EXPECT_EQ(largest_size - 1,
            disk_cache::PreferredCacheSize(largest_size * 100 - 1));

  // Region 6: expected = largest possible size
  EXPECT_EQ(largest_size,
            disk_cache::PreferredCacheSize(largest_size * 100));
  EXPECT_EQ(largest_size,
            disk_cache::PreferredCacheSize(largest_size * 10000));
}

// Tests that we can "migrate" a running instance from one experiment group to
// another.
TEST_F(DiskCacheBackendTest, Histograms) {
  InitCache();
  disk_cache::BackendImpl* backend_ = cache_impl_;  // Needed be the macro.

  for (int i = 1; i < 3; i++) {
    CACHE_UMA(HOURS, "FillupTime", i, 28);
  }
}

// Make sure that we keep the total memory used by the internal buffers under
// control.
TEST_F(DiskCacheBackendTest, TotalBuffersSize1) {
  InitCache();
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 200;
  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kSize));
  CacheTestFillBuffer(buffer->data(), kSize, true);

  for (int i = 0; i < 10; i++) {
    SCOPED_TRACE(i);
    // Allocate 2MB for this entry.
    EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, true));
    EXPECT_EQ(kSize, WriteData(entry, 1, 0, buffer.get(), kSize, true));
    EXPECT_EQ(kSize,
              WriteData(entry, 0, 1024 * 1024, buffer.get(), kSize, false));
    EXPECT_EQ(kSize,
              WriteData(entry, 1, 1024 * 1024, buffer.get(), kSize, false));

    // Delete one of the buffers and truncate the other.
    EXPECT_EQ(0, WriteData(entry, 0, 0, buffer.get(), 0, true));
    EXPECT_EQ(0, WriteData(entry, 1, 10, buffer.get(), 0, true));

    // Delete the second buffer, writing 10 bytes to disk.
    entry->Close();
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  }

  entry->Close();
  EXPECT_EQ(0, cache_impl_->GetTotalBuffersSize());
}

// This test assumes at least 150MB of system memory.
TEST_F(DiskCacheBackendTest, TotalBuffersSize2) {
  InitCache();

  const int kOneMB = 1024 * 1024;
  EXPECT_TRUE(cache_impl_->IsAllocAllowed(0, kOneMB));
  EXPECT_EQ(kOneMB, cache_impl_->GetTotalBuffersSize());

  EXPECT_TRUE(cache_impl_->IsAllocAllowed(0, kOneMB));
  EXPECT_EQ(kOneMB * 2, cache_impl_->GetTotalBuffersSize());

  EXPECT_TRUE(cache_impl_->IsAllocAllowed(0, kOneMB));
  EXPECT_EQ(kOneMB * 3, cache_impl_->GetTotalBuffersSize());

  cache_impl_->BufferDeleted(kOneMB);
  EXPECT_EQ(kOneMB * 2, cache_impl_->GetTotalBuffersSize());

  // Check the upper limit.
  EXPECT_FALSE(cache_impl_->IsAllocAllowed(0, 30 * kOneMB));

  for (int i = 0; i < 30; i++)
    cache_impl_->IsAllocAllowed(0, kOneMB);  // Ignore the result.

  EXPECT_FALSE(cache_impl_->IsAllocAllowed(0, kOneMB));
}

// Tests that sharing of external files works and we are able to delete the
// files when we need to.
TEST_F(DiskCacheBackendTest, FileSharing) {
  InitCache();

  disk_cache::Addr address(0x80000001);
  ASSERT_TRUE(cache_impl_->CreateExternalFile(&address));
  base::FilePath name = cache_impl_->GetFileName(address);

  scoped_refptr<disk_cache::File> file(new disk_cache::File(false));
  file->Init(name);

#if defined(OS_WIN)
  DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE;
  DWORD access = GENERIC_READ | GENERIC_WRITE;
  base::win::ScopedHandle file2(CreateFile(
      name.value().c_str(), access, sharing, NULL, OPEN_EXISTING, 0, NULL));
  EXPECT_FALSE(file2.IsValid());

  sharing |= FILE_SHARE_DELETE;
  file2.Set(CreateFile(name.value().c_str(), access, sharing, NULL,
                       OPEN_EXISTING, 0, NULL));
  EXPECT_TRUE(file2.IsValid());
#endif

  EXPECT_TRUE(base::DeleteFile(name, false));

  // We should be able to use the file.
  const int kSize = 200;
  char buffer1[kSize];
  char buffer2[kSize];
  memset(buffer1, 't', kSize);
  memset(buffer2, 0, kSize);
  EXPECT_TRUE(file->Write(buffer1, kSize, 0));
  EXPECT_TRUE(file->Read(buffer2, kSize, 0));
  EXPECT_EQ(0, memcmp(buffer1, buffer2, kSize));

  EXPECT_TRUE(disk_cache::DeleteCacheFile(name));
}

TEST_F(DiskCacheBackendTest, UpdateRankForExternalCacheHit) {
  InitCache();

  disk_cache::Entry* entry;

  for (int i = 0; i < 2; ++i) {
    std::string key = base::StringPrintf("key%d", i);
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    entry->Close();
  }

  // Ping the oldest entry.
  cache_->OnExternalCacheHit("key0");

  TrimForTest(false);

  // Make sure the older key remains.
  EXPECT_EQ(1, cache_->GetEntryCount());
  ASSERT_THAT(OpenEntry("key0", &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheBackendTest, ShaderCacheUpdateRankForExternalCacheHit) {
  SetCacheType(net::SHADER_CACHE);
  InitCache();

  disk_cache::Entry* entry;

  for (int i = 0; i < 2; ++i) {
    std::string key = base::StringPrintf("key%d", i);
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    entry->Close();
  }

  // Ping the oldest entry.
  cache_->OnExternalCacheHit("key0");

  TrimForTest(false);

  // Make sure the older key remains.
  EXPECT_EQ(1, cache_->GetEntryCount());
  ASSERT_THAT(OpenEntry("key0", &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheBackendTest, SimpleCacheShutdownWithPendingCreate) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendShutdownWithPendingCreate(false);
}

TEST_F(DiskCacheBackendTest, SimpleCacheShutdownWithPendingDoom) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendShutdownWithPendingDoom();
}

TEST_F(DiskCacheBackendTest, SimpleCacheShutdownWithPendingFileIO) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendShutdownWithPendingFileIO(false);
}

TEST_F(DiskCacheBackendTest, SimpleCacheBasics) {
  SetSimpleCacheMode();
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, SimpleCacheAppCacheBasics) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, SimpleCacheKeying) {
  SetSimpleCacheMode();
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, SimpleCacheAppCacheKeying) {
  SetSimpleCacheMode();
  SetCacheType(net::APP_CACHE);
  BackendKeying();
}

// MacOS has a default open file limit of 256 files, which is incompatible with
// this simple cache test.
#if defined(OS_MACOSX)
#define SIMPLE_MAYBE_MACOS(TestName) DISABLED_ ## TestName
#else
#define SIMPLE_MAYBE_MACOS(TestName) TestName
#endif

TEST_F(DiskCacheBackendTest, SIMPLE_MAYBE_MACOS(SimpleCacheLoad)) {
  SetMaxSize(0x100000);
  SetSimpleCacheMode();
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, SIMPLE_MAYBE_MACOS(SimpleCacheAppCacheLoad)) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  SetMaxSize(0x100000);
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, SimpleDoomRecent) {
  SetSimpleCacheMode();
  BackendDoomRecent();
}

// crbug.com/330926, crbug.com/370677
TEST_F(DiskCacheBackendTest, DISABLED_SimpleDoomBetween) {
  SetSimpleCacheMode();
  BackendDoomBetween();
}

TEST_F(DiskCacheBackendTest, SimpleCacheDoomAll) {
  SetSimpleCacheMode();
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, SimpleCacheAppCacheOnlyDoomAll) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, SimpleCacheOpenMissingFile) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";
  disk_cache::Entry* entry = NULL;

  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  ASSERT_TRUE(entry != NULL);
  entry->Close();
  entry = NULL;

  // To make sure the file creation completed we need to call open again so that
  // we block until it actually created the files.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ASSERT_TRUE(entry != NULL);
  entry->Close();
  entry = NULL;

  // Delete one of the files in the entry.
  base::FilePath to_delete_file = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, 0));
  EXPECT_TRUE(base::PathExists(to_delete_file));
  EXPECT_TRUE(disk_cache::DeleteCacheFile(to_delete_file));

  // Failing to open the entry should delete the rest of these files.
  ASSERT_THAT(OpenEntry(key, &entry), IsError(net::ERR_FAILED));

  // Confirm the rest of the files are gone.
  for (int i = 1; i < disk_cache::kSimpleEntryFileCount; ++i) {
    base::FilePath should_be_gone_file(cache_path_.AppendASCII(
        disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, i)));
    EXPECT_FALSE(base::PathExists(should_be_gone_file));
  }
}

TEST_F(DiskCacheBackendTest, SimpleCacheOpenBadFile) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";
  disk_cache::Entry* entry = NULL;

  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  disk_cache::Entry* null = NULL;
  ASSERT_NE(null, entry);
  entry->Close();
  entry = NULL;

  // To make sure the file creation completed we need to call open again so that
  // we block until it actually created the files.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ASSERT_NE(null, entry);
  entry->Close();
  entry = NULL;

  // The entry is being closed on the Simple Cache worker pool
  disk_cache::SimpleBackendImpl::FlushWorkerPoolForTesting();
  base::RunLoop().RunUntilIdle();

  // Write an invalid header for stream 0 and stream 1.
  base::FilePath entry_file1_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, 0));

  disk_cache::SimpleFileHeader header;
  header.initial_magic_number = UINT64_C(0xbadf00d);
  EXPECT_EQ(static_cast<int>(sizeof(header)),
            base::WriteFile(entry_file1_path, reinterpret_cast<char*>(&header),
                            sizeof(header)));
  ASSERT_THAT(OpenEntry(key, &entry), IsError(net::ERR_FAILED));
}

// Tests that the Simple Cache Backend fails to initialize with non-matching
// file structure on disk.
TEST_F(DiskCacheBackendTest, SimpleCacheOverBlockfileCache) {
  // Create a cache structure with the |BackendImpl|.
  InitCache();
  disk_cache::Entry* entry;
  const int kSize = 50;
  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kSize));
  CacheTestFillBuffer(buffer->data(), kSize, false);
  ASSERT_THAT(CreateEntry("key", &entry), IsOk());
  ASSERT_EQ(0, WriteData(entry, 0, 0, buffer.get(), 0, false));
  entry->Close();
  cache_.reset();

  // Check that the |SimpleBackendImpl| does not favor this structure.
  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
      base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));
  disk_cache::SimpleBackendImpl* simple_cache =
      new disk_cache::SimpleBackendImpl(
          cache_path_, 0, net::DISK_CACHE, cache_thread.task_runner(), NULL);
  net::TestCompletionCallback cb;
  int rv = simple_cache->Init(cb.callback());
  EXPECT_NE(net::OK, cb.GetResult(rv));
  delete simple_cache;
  DisableIntegrityCheck();
}

// Tests that the |BackendImpl| refuses to initialize on top of the files
// generated by the Simple Cache Backend.
TEST_F(DiskCacheBackendTest, BlockfileCacheOverSimpleCache) {
  // Create a cache structure with the |SimpleBackendImpl|.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* entry;
  const int kSize = 50;
  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kSize));
  CacheTestFillBuffer(buffer->data(), kSize, false);
  ASSERT_THAT(CreateEntry("key", &entry), IsOk());
  ASSERT_EQ(0, WriteData(entry, 0, 0, buffer.get(), 0, false));
  entry->Close();
  cache_.reset();

  // Check that the |BackendImpl| does not favor this structure.
  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
      base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));
  disk_cache::BackendImpl* cache = new disk_cache::BackendImpl(
      cache_path_, base::ThreadTaskRunnerHandle::Get(), NULL);
  cache->SetUnitTestMode();
  net::TestCompletionCallback cb;
  int rv = cache->Init(cb.callback());
  EXPECT_NE(net::OK, cb.GetResult(rv));
  delete cache;
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, SimpleCacheFixEnumerators) {
  SetSimpleCacheMode();
  BackendFixEnumerators();
}

// Tests basic functionality of the SimpleBackend implementation of the
// enumeration API.
TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationBasics) {
  SetSimpleCacheMode();
  InitCache();
  std::set<std::string> key_pool;
  ASSERT_TRUE(CreateSetOfRandomEntries(&key_pool));

  // Check that enumeration returns all entries.
  std::set<std::string> keys_to_match(key_pool);
  std::unique_ptr<TestIterator> iter = CreateIterator();
  size_t count = 0;
  ASSERT_TRUE(EnumerateAndMatchKeys(-1, iter.get(), &keys_to_match, &count));
  iter.reset();
  EXPECT_EQ(key_pool.size(), count);
  EXPECT_TRUE(keys_to_match.empty());

  // Check that opening entries does not affect enumeration.
  keys_to_match = key_pool;
  iter = CreateIterator();
  count = 0;
  disk_cache::Entry* entry_opened_before;
  ASSERT_THAT(OpenEntry(*(key_pool.begin()), &entry_opened_before), IsOk());
  ASSERT_TRUE(EnumerateAndMatchKeys(key_pool.size()/2,
                                    iter.get(),
                                    &keys_to_match,
                                    &count));

  disk_cache::Entry* entry_opened_middle;
  ASSERT_EQ(net::OK,
            OpenEntry(*(keys_to_match.begin()), &entry_opened_middle));
  ASSERT_TRUE(EnumerateAndMatchKeys(-1, iter.get(), &keys_to_match, &count));
  iter.reset();
  entry_opened_before->Close();
  entry_opened_middle->Close();

  EXPECT_EQ(key_pool.size(), count);
  EXPECT_TRUE(keys_to_match.empty());
}

// Tests that the enumerations are not affected by dooming an entry in the
// middle.
TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationWhileDoomed) {
  SetSimpleCacheMode();
  InitCache();
  std::set<std::string> key_pool;
  ASSERT_TRUE(CreateSetOfRandomEntries(&key_pool));

  // Check that enumeration returns all entries but the doomed one.
  std::set<std::string> keys_to_match(key_pool);
  std::unique_ptr<TestIterator> iter = CreateIterator();
  size_t count = 0;
  ASSERT_TRUE(EnumerateAndMatchKeys(key_pool.size()/2,
                                    iter.get(),
                                    &keys_to_match,
                                    &count));

  std::string key_to_delete = *(keys_to_match.begin());
  DoomEntry(key_to_delete);
  keys_to_match.erase(key_to_delete);
  key_pool.erase(key_to_delete);
  ASSERT_TRUE(EnumerateAndMatchKeys(-1, iter.get(), &keys_to_match, &count));
  iter.reset();

  EXPECT_EQ(key_pool.size(), count);
  EXPECT_TRUE(keys_to_match.empty());
}

// This test is flaky on Android Marshmallow crbug.com/638891.
#if !defined(OS_ANDROID)
// Tests that enumerations are not affected by corrupt files.
TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationCorruption) {
  SetSimpleCacheMode();
  InitCache();
  // Create a corrupt entry. The write/read sequence ensures that the entry will
  // have been created before corrupting the platform files, in the case of
  // optimistic operations.
  const std::string key = "the key";
  disk_cache::Entry* corrupted_entry;

  ASSERT_THAT(CreateEntry(key, &corrupted_entry), IsOk());
  ASSERT_TRUE(corrupted_entry);
  const int kSize = 50;
  scoped_refptr<net::IOBuffer> buffer(new net::IOBuffer(kSize));
  CacheTestFillBuffer(buffer->data(), kSize, false);
  ASSERT_EQ(kSize,
            WriteData(corrupted_entry, 0, 0, buffer.get(), kSize, false));
  ASSERT_EQ(kSize, ReadData(corrupted_entry, 0, 0, buffer.get(), kSize));
  corrupted_entry->Close();

  std::set<std::string> key_pool;
  ASSERT_TRUE(CreateSetOfRandomEntries(&key_pool));

  EXPECT_TRUE(disk_cache::simple_util::CreateCorruptFileForTests(
      key, cache_path_));
  EXPECT_EQ(key_pool.size() + 1, static_cast<size_t>(cache_->GetEntryCount()));

  // Check that enumeration returns all entries but the corrupt one.
  std::set<std::string> keys_to_match(key_pool);
  std::unique_ptr<TestIterator> iter = CreateIterator();
  size_t count = 0;
  ASSERT_TRUE(EnumerateAndMatchKeys(-1, iter.get(), &keys_to_match, &count));
  iter.reset();

  EXPECT_EQ(key_pool.size(), count);
  EXPECT_TRUE(keys_to_match.empty());
}
#endif

// Tests that enumerations don't leak memory when the backend is destructed
// mid-enumeration.
TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationDestruction) {
  SetSimpleCacheMode();
  InitCache();
  std::set<std::string> key_pool;
  ASSERT_TRUE(CreateSetOfRandomEntries(&key_pool));

  std::unique_ptr<TestIterator> iter = CreateIterator();
  disk_cache::Entry* entry = NULL;
  ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
  EXPECT_TRUE(entry);
  disk_cache::ScopedEntryPtr entry_closer(entry);

  cache_.reset();
  // This test passes if we don't leak memory.
}

// Tests that enumerations include entries with long keys.
TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationLongKeys) {
  SetSimpleCacheMode();
  InitCache();
  std::set<std::string> key_pool;
  ASSERT_TRUE(CreateSetOfRandomEntries(&key_pool));

  const size_t long_key_length =
      disk_cache::SimpleSynchronousEntry::kInitialHeaderRead + 10;
  std::string long_key(long_key_length, 'X');
  key_pool.insert(long_key);
  disk_cache::Entry* entry = NULL;
  ASSERT_THAT(CreateEntry(long_key.c_str(), &entry), IsOk());
  entry->Close();

  std::unique_ptr<TestIterator> iter = CreateIterator();
  size_t count = 0;
  EXPECT_TRUE(EnumerateAndMatchKeys(-1, iter.get(), &key_pool, &count));
  EXPECT_TRUE(key_pool.empty());
}

// Tests that a SimpleCache doesn't crash when files are deleted very quickly
// after closing.
// NOTE: IF THIS TEST IS FLAKY THEN IT IS FAILING. See https://crbug.com/416940
TEST_F(DiskCacheBackendTest, SimpleCacheDeleteQuickly) {
  SetSimpleCacheMode();
  for (int i = 0; i < 100; ++i) {
    InitCache();
    cache_.reset();
    EXPECT_TRUE(CleanupCacheDir());
  }
}

TEST_F(DiskCacheBackendTest, SimpleCacheLateDoom) {
  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(CreateEntry("first", &entry1), IsOk());
  ASSERT_THAT(CreateEntry("second", &entry2), IsOk());
  entry1->Close();

  // Ensure that the directory mtime is flushed to disk before serializing the
  // index.
  disk_cache::SimpleBackendImpl::FlushWorkerPoolForTesting();
  base::RunLoop().RunUntilIdle();
#if defined(OS_POSIX)
  base::File cache_dir(cache_path_,
                       base::File::FLAG_OPEN | base::File::FLAG_READ);
  EXPECT_TRUE(cache_dir.Flush());
#endif  // defined(OS_POSIX)
  cache_.reset();

  // The index is now written. Dooming the last entry can't delete a file,
  // because that would advance the cache directory mtime and invalidate the
  // index.
  entry2->Doom();
  entry2->Close();

  DisableFirstCleanup();
  InitCache();
  EXPECT_EQ(disk_cache::SimpleIndex::INITIALIZE_METHOD_LOADED,
            simple_cache_impl_->index()->init_method());
}
