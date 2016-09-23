// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/file_path.h"
#include "net/disk_cache/blockfile/disk_format.h"
#include "net/disk_cache/blockfile/storage_block-inl.h"
#include "net/disk_cache/blockfile/storage_block.h"
#include "net/disk_cache/disk_cache_test_base.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

typedef disk_cache::StorageBlock<disk_cache::EntryStore> CacheEntryBlock;

TEST_F(DiskCacheTest, StorageBlock_LoadStore) {
  base::FilePath filename = cache_path_.AppendASCII("a_test");
  scoped_refptr<disk_cache::MappedFile> file(new disk_cache::MappedFile);
  ASSERT_TRUE(CreateCacheTestFile(filename));
  ASSERT_TRUE(file->Init(filename, 8192));

  CacheEntryBlock entry1(file.get(), disk_cache::Addr(0xa0010001));
  memset(entry1.Data(), 0, sizeof(disk_cache::EntryStore));
  entry1.Data()->hash = 0xaa5555aa;
  entry1.Data()->rankings_node = 0xa0010002;

  EXPECT_TRUE(entry1.Store());
  entry1.Data()->hash = 0x88118811;
  entry1.Data()->rankings_node = 0xa0040009;

  EXPECT_TRUE(entry1.Load());
  EXPECT_EQ(0xaa5555aa, entry1.Data()->hash);
  EXPECT_EQ(0xa0010002, entry1.Data()->rankings_node);
}

TEST_F(DiskCacheTest, StorageBlock_SetData) {
  base::FilePath filename = cache_path_.AppendASCII("a_test");
  scoped_refptr<disk_cache::MappedFile> file(new disk_cache::MappedFile);
  ASSERT_TRUE(CreateCacheTestFile(filename));
  ASSERT_TRUE(file->Init(filename, 8192));

  CacheEntryBlock entry1(file.get(), disk_cache::Addr(0xa0010001));
  entry1.Data()->hash = 0xaa5555aa;

  CacheEntryBlock entry2(file.get(), disk_cache::Addr(0xa0010002));
  EXPECT_TRUE(entry2.Load());
  EXPECT_TRUE(entry2.Data() != NULL);
  EXPECT_TRUE(0 == entry2.Data()->hash);

  EXPECT_TRUE(entry2.Data() != entry1.Data());
  entry2.SetData(entry1.Data());
  EXPECT_EQ(0xaa5555aa, entry2.Data()->hash);
  EXPECT_TRUE(entry2.Data() == entry1.Data());
}

TEST_F(DiskCacheTest, StorageBlock_SetModified) {
  base::FilePath filename = cache_path_.AppendASCII("a_test");
  scoped_refptr<disk_cache::MappedFile> file(new disk_cache::MappedFile);
  ASSERT_TRUE(CreateCacheTestFile(filename));
  ASSERT_TRUE(file->Init(filename, 8192));

  CacheEntryBlock* entry1 =
      new CacheEntryBlock(file.get(), disk_cache::Addr(0xa0010003));
  EXPECT_TRUE(entry1->Load());
  EXPECT_TRUE(0 == entry1->Data()->hash);
  entry1->Data()->hash = 0x45687912;
  entry1->set_modified();
  delete entry1;

  CacheEntryBlock entry2(file.get(), disk_cache::Addr(0xa0010003));
  EXPECT_TRUE(entry2.Load());
  EXPECT_TRUE(0x45687912 == entry2.Data()->hash);
}
