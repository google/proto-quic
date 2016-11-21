// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_header_indexing.h"

#include "base/memory/ptr_util.h"
#include "base/strings/string_piece.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/platform_test.h"

using base::StringPiece;

namespace net {

namespace test {

class HeaderIndexingPeer {
 public:
  HeaderIndexingPeer() : hi_() {}

  void CreateTestInit() {
    std::string input[] = {"key1", "key2", "key3"};
    hi_.indexing_set_ =
        HeaderIndexing::HeaderSet(input, input + arraysize(input));
    hi_.tracking_set_ =
        HeaderIndexing::HeaderSet(input, input + arraysize(input));
  }

  bool ShouldIndex(StringPiece header) { return hi_.ShouldIndex(header, ""); }

  void CreateInitIndexingHeaders() { hi_.CreateInitIndexingHeaders(); }

  void TryInsert(std::string&& header) {
    hi_.TryInsertHeader(std::move(header), &(hi_.indexing_set_),
                        hi_.indexing_set_bound_);
  }

  bool InTrackingSet(std::string str) {
    return hi_.tracking_set_.find(str) != hi_.tracking_set_.end();
  }

  size_t indexing_set_size() const { return hi_.indexing_set_.size(); }

  size_t tracking_set_size() const { return hi_.tracking_set_.size(); }

  HeaderIndexing::HeaderSet* indexing_set() { return &(hi_.indexing_set_); }

  HeaderIndexing::HeaderSet* tracking_set() { return &(hi_.tracking_set_); }

 private:
  HeaderIndexing hi_;
};

class SpdyHeaderIndexingTest : public ::testing::Test {
 protected:
  SpdyHeaderIndexingTest() {
    FLAGS_gfe_spdy_indexing_set_bound = 3;
    FLAGS_gfe_spdy_tracking_set_bound = 4;
    hi_ = base::MakeUnique<HeaderIndexingPeer>();
    hi_->CreateTestInit();
  }
  void SetUp() override {
    EXPECT_EQ(3u, hi_->indexing_set_size());
    EXPECT_EQ(3u, hi_->tracking_set_size());
  }
  std::unique_ptr<HeaderIndexingPeer> hi_;
};

TEST_F(SpdyHeaderIndexingTest, TestTryInsertHeader) {
  std::string key("key4");
  hi_->TryInsert(std::move(key));
  EXPECT_EQ(3u, hi_->indexing_set_size());
  EXPECT_TRUE(hi_->ShouldIndex("key4"));
}

TEST_F(SpdyHeaderIndexingTest, TestShouldIndex) {
  std::string key3 = "key3";
  std::string key4 = "key4";
  std::string key5 = "key5";
  // Cache hit.
  EXPECT_TRUE(hi_->ShouldIndex(key3));
  EXPECT_EQ(3u, hi_->indexing_set_size());
  EXPECT_EQ(3u, hi_->tracking_set_size());

  // Cache miss. Add to tracking set.
  EXPECT_FALSE(hi_->ShouldIndex(key4));
  EXPECT_EQ(3u, hi_->indexing_set_size());
  EXPECT_EQ(4u, hi_->tracking_set_size());
  EXPECT_TRUE(hi_->InTrackingSet(key4));
  // Cache miss. Add to indexing set by kicking one entry out.
  EXPECT_FALSE(hi_->ShouldIndex(key4));
  EXPECT_EQ(3u, hi_->indexing_set_size());
  EXPECT_EQ(4u, hi_->tracking_set_size());
  EXPECT_TRUE(hi_->InTrackingSet(key4));
  // Cache hit.
  EXPECT_TRUE(hi_->ShouldIndex(key4));

  // Cache miss. Add to tracking set by kicking one entry out.
  EXPECT_FALSE(hi_->ShouldIndex(key5));
  EXPECT_EQ(3u, hi_->indexing_set_size());
  EXPECT_EQ(4u, hi_->tracking_set_size());
  EXPECT_TRUE(hi_->ShouldIndex(key4));
  EXPECT_TRUE(hi_->InTrackingSet(key5));
  // Cache miss. Add to indexing set by kicking one entry out.
  EXPECT_FALSE(hi_->ShouldIndex(key5));
  EXPECT_EQ(3u, hi_->indexing_set_size());
  EXPECT_EQ(4u, hi_->tracking_set_size());
  EXPECT_TRUE(hi_->ShouldIndex(key5));
  EXPECT_TRUE(hi_->InTrackingSet(key5));
}

TEST_F(SpdyHeaderIndexingTest, TestSetInit) {
  hi_->CreateInitIndexingHeaders();
  EXPECT_EQ(100u, hi_->indexing_set_size());
  EXPECT_EQ(100u, hi_->tracking_set_size());
  EXPECT_TRUE(hi_->ShouldIndex(":status"));
  EXPECT_TRUE(hi_->InTrackingSet(":status"));
  EXPECT_FALSE(hi_->InTrackingSet("NotValid"));
  EXPECT_FALSE(hi_->ShouldIndex("NotValid"));
}

}  // namespace test

}  // namespace net
