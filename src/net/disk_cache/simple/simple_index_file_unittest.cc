// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/simple/simple_index_file.h"

#include <memory>

#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/hash.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/pickle.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "net/base/cache_type.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_backend_version.h"
#include "net/disk_cache/simple/simple_entry_format.h"
#include "net/disk_cache/simple/simple_index.h"
#include "net/disk_cache/simple/simple_util.h"
#include "net/disk_cache/simple/simple_version_upgrade.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsOk;

using base::Time;
using disk_cache::SimpleIndexFile;
using disk_cache::SimpleIndex;

namespace disk_cache {

// The Simple Cache backend requires a few guarantees from the filesystem like
// atomic renaming of recently open files. Those guarantees are not provided in
// general on Windows.
#if defined(OS_POSIX)

TEST(IndexMetadataTest, Basics) {
  SimpleIndexFile::IndexMetadata index_metadata;

  EXPECT_EQ(disk_cache::kSimpleIndexMagicNumber, index_metadata.magic_number_);
  EXPECT_EQ(disk_cache::kSimpleVersion, index_metadata.version_);
  EXPECT_EQ(0U, index_metadata.entry_count());
  EXPECT_EQ(0U, index_metadata.cache_size_);

  // Without setting a |reason_|, the index metadata isn't valid.
  index_metadata.reason_ = SimpleIndex::INDEX_WRITE_REASON_SHUTDOWN;

  EXPECT_TRUE(index_metadata.CheckIndexMetadata());
}

TEST(IndexMetadataTest, Serialize) {
  SimpleIndexFile::IndexMetadata index_metadata(
      SimpleIndex::INDEX_WRITE_REASON_SHUTDOWN, 123, 456);
  base::Pickle pickle;
  index_metadata.Serialize(&pickle);
  base::PickleIterator it(pickle);
  SimpleIndexFile::IndexMetadata new_index_metadata;
  new_index_metadata.Deserialize(&it);

  EXPECT_EQ(new_index_metadata.magic_number_, index_metadata.magic_number_);
  EXPECT_EQ(new_index_metadata.version_, index_metadata.version_);
  EXPECT_EQ(new_index_metadata.reason_, index_metadata.reason_);
  EXPECT_EQ(new_index_metadata.entry_count(), index_metadata.entry_count());
  EXPECT_EQ(new_index_metadata.cache_size_, index_metadata.cache_size_);

  EXPECT_TRUE(new_index_metadata.CheckIndexMetadata());
}

// This derived index metadata class allows us to serialize the older V6 format
// of the index metadata, thus allowing us to test deserializing the old format.
class V6IndexMetadataForTest : public SimpleIndexFile::IndexMetadata {
 public:
  // Do not default to |SimpleIndex::INDEX_WRITE_REASON_MAX|, because we want to
  // ensure we don't serialize that value and then deserialize it and have a
  // false positive result.
  V6IndexMetadataForTest(uint64_t entry_count, uint64_t cache_size)
      : SimpleIndexFile::IndexMetadata(SimpleIndex::INDEX_WRITE_REASON_SHUTDOWN,
                                       entry_count,
                                       cache_size) {
    version_ = 6;
  }

  // Copied and pasted from the V6 implementation of
  // |SimpleIndexFile::IndexMetadata()| (removing DCHECKs).
  void Serialize(base::Pickle* pickle) const override {
    pickle->WriteUInt64(magic_number_);
    pickle->WriteUInt32(version_);
    pickle->WriteUInt64(entry_count_);
    pickle->WriteUInt64(cache_size_);
  }
};

TEST(IndexMetadataTest, ReadV6Format) {
  V6IndexMetadataForTest v6_index_metadata(123, 456);
  EXPECT_EQ(6U, v6_index_metadata.version_);
  base::Pickle pickle;
  v6_index_metadata.Serialize(&pickle);
  base::PickleIterator it(pickle);
  SimpleIndexFile::IndexMetadata new_index_metadata;
  new_index_metadata.Deserialize(&it);

  EXPECT_EQ(new_index_metadata.magic_number_, v6_index_metadata.magic_number_);
  EXPECT_EQ(new_index_metadata.version_, v6_index_metadata.version_);

  EXPECT_EQ(new_index_metadata.reason_, SimpleIndex::INDEX_WRITE_REASON_MAX);
  EXPECT_EQ(new_index_metadata.entry_count(), v6_index_metadata.entry_count());
  EXPECT_EQ(new_index_metadata.cache_size_, v6_index_metadata.cache_size_);

  EXPECT_TRUE(new_index_metadata.CheckIndexMetadata());
}

// This friend derived class is able to reexport its ancestors private methods
// as public, for use in tests.
class WrappedSimpleIndexFile : public SimpleIndexFile {
 public:
  using SimpleIndexFile::Deserialize;
  using SimpleIndexFile::LegacyIsIndexFileStale;
  using SimpleIndexFile::Serialize;
  using SimpleIndexFile::SerializeFinalData;

  explicit WrappedSimpleIndexFile(const base::FilePath& index_file_directory)
      : SimpleIndexFile(base::ThreadTaskRunnerHandle::Get(),
                        base::ThreadTaskRunnerHandle::Get(),
                        net::DISK_CACHE,
                        index_file_directory) {}
  ~WrappedSimpleIndexFile() override {}

  const base::FilePath& GetIndexFilePath() const {
    return index_file_;
  }

  const base::FilePath& GetTempIndexFilePath() const {
    return temp_index_file_;
  }

  bool CreateIndexFileDirectory() const {
    return base::CreateDirectory(index_file_.DirName());
  }
};

class SimpleIndexFileTest : public testing::Test {
 public:
  bool CompareTwoEntryMetadata(const EntryMetadata& a, const EntryMetadata& b) {
    return
        a.last_used_time_seconds_since_epoch_ ==
            b.last_used_time_seconds_since_epoch_ &&
        a.entry_size_ == b.entry_size_;
  }
};

TEST_F(SimpleIndexFileTest, Serialize) {
  SimpleIndex::EntrySet entries;
  static const uint64_t kHashes[] = {11, 22, 33};
  static const size_t kNumHashes = arraysize(kHashes);
  EntryMetadata metadata_entries[kNumHashes];

  SimpleIndexFile::IndexMetadata index_metadata(
      SimpleIndex::INDEX_WRITE_REASON_SHUTDOWN,
      static_cast<uint64_t>(kNumHashes), 456);
  for (size_t i = 0; i < kNumHashes; ++i) {
    uint64_t hash = kHashes[i];
    // TODO(eroman): Should restructure the test so no casting here (and same
    //               elsewhere where a hash is cast to an entry size).
    metadata_entries[i] = EntryMetadata(Time(), static_cast<uint32_t>(hash));
    SimpleIndex::InsertInEntrySet(hash, metadata_entries[i], &entries);
  }

  std::unique_ptr<base::Pickle> pickle =
      WrappedSimpleIndexFile::Serialize(index_metadata, entries);
  EXPECT_TRUE(pickle.get() != NULL);
  base::Time now = base::Time::Now();
  EXPECT_TRUE(WrappedSimpleIndexFile::SerializeFinalData(now, pickle.get()));
  base::Time when_index_last_saw_cache;
  SimpleIndexLoadResult deserialize_result;
  WrappedSimpleIndexFile::Deserialize(static_cast<const char*>(pickle->data()),
                                      pickle->size(),
                                      &when_index_last_saw_cache,
                                      &deserialize_result);
  EXPECT_TRUE(deserialize_result.did_load);
  EXPECT_EQ(now, when_index_last_saw_cache);
  const SimpleIndex::EntrySet& new_entries = deserialize_result.entries;
  EXPECT_EQ(entries.size(), new_entries.size());

  for (size_t i = 0; i < kNumHashes; ++i) {
    SimpleIndex::EntrySet::const_iterator it = new_entries.find(kHashes[i]);
    EXPECT_TRUE(new_entries.end() != it);
    EXPECT_TRUE(CompareTwoEntryMetadata(it->second, metadata_entries[i]));
  }
}

TEST_F(SimpleIndexFileTest, LegacyIsIndexFileStale) {
  base::ScopedTempDir cache_dir;
  ASSERT_TRUE(cache_dir.CreateUniqueTempDir());
  base::Time cache_mtime;
  const base::FilePath cache_path = cache_dir.GetPath();

  ASSERT_TRUE(simple_util::GetMTime(cache_path, &cache_mtime));
  WrappedSimpleIndexFile simple_index_file(cache_path);
  ASSERT_TRUE(simple_index_file.CreateIndexFileDirectory());
  const base::FilePath& index_path = simple_index_file.GetIndexFilePath();
  EXPECT_TRUE(
      WrappedSimpleIndexFile::LegacyIsIndexFileStale(cache_mtime, index_path));
  const std::string kDummyData = "nothing to be seen here";
  EXPECT_EQ(static_cast<int>(kDummyData.size()),
            base::WriteFile(index_path,
                            kDummyData.data(), kDummyData.size()));
  ASSERT_TRUE(simple_util::GetMTime(cache_path, &cache_mtime));
  EXPECT_FALSE(
      WrappedSimpleIndexFile::LegacyIsIndexFileStale(cache_mtime, index_path));

  const base::Time past_time = base::Time::Now() -
      base::TimeDelta::FromSeconds(10);
  EXPECT_TRUE(base::TouchFile(index_path, past_time, past_time));
  EXPECT_TRUE(base::TouchFile(cache_path, past_time, past_time));
  ASSERT_TRUE(simple_util::GetMTime(cache_path, &cache_mtime));
  EXPECT_FALSE(
      WrappedSimpleIndexFile::LegacyIsIndexFileStale(cache_mtime, index_path));
  const base::Time even_older = past_time - base::TimeDelta::FromSeconds(10);
  EXPECT_TRUE(base::TouchFile(index_path, even_older, even_older));
  EXPECT_TRUE(
      WrappedSimpleIndexFile::LegacyIsIndexFileStale(cache_mtime, index_path));
}

TEST_F(SimpleIndexFileTest, WriteThenLoadIndex) {
  base::ScopedTempDir cache_dir;
  ASSERT_TRUE(cache_dir.CreateUniqueTempDir());

  SimpleIndex::EntrySet entries;
  static const uint64_t kHashes[] = {11, 22, 33};
  static const size_t kNumHashes = arraysize(kHashes);
  EntryMetadata metadata_entries[kNumHashes];
  for (size_t i = 0; i < kNumHashes; ++i) {
    uint64_t hash = kHashes[i];
    metadata_entries[i] = EntryMetadata(Time(), static_cast<uint32_t>(hash));
    SimpleIndex::InsertInEntrySet(hash, metadata_entries[i], &entries);
  }

  const uint64_t kCacheSize = 456U;
  net::TestClosure closure;
  {
    WrappedSimpleIndexFile simple_index_file(cache_dir.GetPath());
    simple_index_file.WriteToDisk(SimpleIndex::INDEX_WRITE_REASON_SHUTDOWN,
                                  entries, kCacheSize, base::TimeTicks(), false,
                                  closure.closure());
    closure.WaitForResult();
    EXPECT_TRUE(base::PathExists(simple_index_file.GetIndexFilePath()));
  }

  WrappedSimpleIndexFile simple_index_file(cache_dir.GetPath());
  base::Time fake_cache_mtime;
  ASSERT_TRUE(simple_util::GetMTime(cache_dir.GetPath(), &fake_cache_mtime));
  SimpleIndexLoadResult load_index_result;
  simple_index_file.LoadIndexEntries(fake_cache_mtime, closure.closure(),
                                     &load_index_result);
  closure.WaitForResult();

  EXPECT_TRUE(base::PathExists(simple_index_file.GetIndexFilePath()));
  EXPECT_TRUE(load_index_result.did_load);
  EXPECT_FALSE(load_index_result.flush_required);

  EXPECT_EQ(kNumHashes, load_index_result.entries.size());
  for (size_t i = 0; i < kNumHashes; ++i)
    EXPECT_EQ(1U, load_index_result.entries.count(kHashes[i]));
}

TEST_F(SimpleIndexFileTest, LoadCorruptIndex) {
  base::ScopedTempDir cache_dir;
  ASSERT_TRUE(cache_dir.CreateUniqueTempDir());

  WrappedSimpleIndexFile simple_index_file(cache_dir.GetPath());
  ASSERT_TRUE(simple_index_file.CreateIndexFileDirectory());
  const base::FilePath& index_path = simple_index_file.GetIndexFilePath();
  const std::string kDummyData = "nothing to be seen here";
  EXPECT_EQ(static_cast<int>(kDummyData.size()),
            base::WriteFile(index_path, kDummyData.data(), kDummyData.size()));
  base::Time fake_cache_mtime;
  ASSERT_TRUE(simple_util::GetMTime(simple_index_file.GetIndexFilePath(),
                                    &fake_cache_mtime));
  EXPECT_FALSE(WrappedSimpleIndexFile::LegacyIsIndexFileStale(fake_cache_mtime,
                                                              index_path));
  SimpleIndexLoadResult load_index_result;
  net::TestClosure closure;
  simple_index_file.LoadIndexEntries(fake_cache_mtime, closure.closure(),
                                     &load_index_result);
  closure.WaitForResult();

  EXPECT_FALSE(base::PathExists(index_path));
  EXPECT_TRUE(load_index_result.did_load);
  EXPECT_TRUE(load_index_result.flush_required);
}

// Tests that after an upgrade the backend has the index file put in place.
TEST_F(SimpleIndexFileTest, SimpleCacheUpgrade) {
  base::ScopedTempDir cache_dir;
  ASSERT_TRUE(cache_dir.CreateUniqueTempDir());
  const base::FilePath cache_path = cache_dir.GetPath();

  // Write an old fake index file.
  base::File file(cache_path.AppendASCII("index"),
                  base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  ASSERT_TRUE(file.IsValid());
  disk_cache::FakeIndexData file_contents;
  file_contents.initial_magic_number = disk_cache::kSimpleInitialMagicNumber;
  file_contents.version = 5;
  int bytes_written = file.Write(0, reinterpret_cast<char*>(&file_contents),
                                 sizeof(file_contents));
  ASSERT_EQ((int)sizeof(file_contents), bytes_written);
  file.Close();

  // Write the index file. The format is incorrect, but for transitioning from
  // v5 it does not matter.
  const std::string index_file_contents("incorrectly serialized data");
  const base::FilePath old_index_file =
      cache_path.AppendASCII("the-real-index");
  ASSERT_EQ(static_cast<int>(index_file_contents.size()),
            base::WriteFile(old_index_file, index_file_contents.data(),
                            index_file_contents.size()));

  // Upgrade the cache.
  ASSERT_TRUE(
      disk_cache::UpgradeSimpleCacheOnDisk(cache_path, SimpleExperiment()));

  // Create the backend and initiate index flush by destroying the backend.
  base::Thread cache_thread("CacheThread");
  ASSERT_TRUE(cache_thread.StartWithOptions(
      base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));
  disk_cache::SimpleBackendImpl* simple_cache =
      new disk_cache::SimpleBackendImpl(cache_path, 0, net::DISK_CACHE,
                                        cache_thread.task_runner().get(), NULL);
  net::TestCompletionCallback cb;
  int rv = simple_cache->Init(cb.callback());
  EXPECT_THAT(cb.GetResult(rv), IsOk());
  rv = simple_cache->index()->ExecuteWhenReady(cb.callback());
  EXPECT_THAT(cb.GetResult(rv), IsOk());
  delete simple_cache;

  // The backend flushes the index on destruction and does so on the cache
  // thread, wait for the flushing to finish by posting a callback to the cache
  // thread after that.
  MessageLoopHelper helper;
  CallbackTest cb_shutdown(&helper, false);
  cache_thread.task_runner()->PostTaskAndReply(
      FROM_HERE, base::Bind(&base::DoNothing),
      base::Bind(&CallbackTest::Run, base::Unretained(&cb_shutdown), net::OK));
  helper.WaitUntilCacheIoFinished(1);

  // Verify that the index file exists.
  const base::FilePath& index_file_path =
      cache_path.AppendASCII("index-dir").AppendASCII("the-real-index");
  EXPECT_TRUE(base::PathExists(index_file_path));

  // Verify that the version of the index file is correct.
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(index_file_path, &contents));
  base::Time when_index_last_saw_cache;
  SimpleIndexLoadResult deserialize_result;
  WrappedSimpleIndexFile::Deserialize(contents.data(),
                                      contents.size(),
                                      &when_index_last_saw_cache,
                                      &deserialize_result);
  EXPECT_TRUE(deserialize_result.did_load);
}

TEST_F(SimpleIndexFileTest, OverwritesStaleTempFile) {
  base::ScopedTempDir cache_dir;
  ASSERT_TRUE(cache_dir.CreateUniqueTempDir());
  const base::FilePath cache_path = cache_dir.GetPath();
  WrappedSimpleIndexFile simple_index_file(cache_path);
  ASSERT_TRUE(simple_index_file.CreateIndexFileDirectory());

  // Create an temporary index file.
  const base::FilePath& temp_index_path =
      simple_index_file.GetTempIndexFilePath();
  const std::string kDummyData = "nothing to be seen here";
  EXPECT_EQ(
      static_cast<int>(kDummyData.size()),
      base::WriteFile(temp_index_path, kDummyData.data(), kDummyData.size()));
  ASSERT_TRUE(base::PathExists(simple_index_file.GetTempIndexFilePath()));

  // Write the index file.
  SimpleIndex::EntrySet entries;
  SimpleIndex::InsertInEntrySet(11, EntryMetadata(Time(), 11u), &entries);
  net::TestClosure closure;
  simple_index_file.WriteToDisk(SimpleIndex::INDEX_WRITE_REASON_SHUTDOWN,
                                entries, 120U, base::TimeTicks(), false,
                                closure.closure());
  closure.WaitForResult();

  // Check that the temporary file was deleted and the index file was created.
  EXPECT_FALSE(base::PathExists(simple_index_file.GetTempIndexFilePath()));
  EXPECT_TRUE(base::PathExists(simple_index_file.GetIndexFilePath()));
}

#endif  // defined(OS_POSIX)

}  // namespace disk_cache
