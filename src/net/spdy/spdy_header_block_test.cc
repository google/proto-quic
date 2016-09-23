// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_header_block.h"

#include <memory>
#include <utility>

#include "base/values.h"
#include "net/log/net_log.h"
#include "net/spdy/spdy_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::make_pair;
using std::string;
using ::testing::ElementsAre;

namespace net {
namespace test {

class StringPieceProxyPeer {
 public:
  static base::StringPiece key(SpdyHeaderBlock::StringPieceProxy* p) {
    return p->key_;
  }
};

std::pair<base::StringPiece, base::StringPiece> Pair(base::StringPiece k,
                                                     base::StringPiece v) {
  return make_pair(k, v);
}

// This test verifies that SpdyHeaderBlock behaves correctly when empty.
TEST(SpdyHeaderBlockTest, EmptyBlock) {
  SpdyHeaderBlock block;
  EXPECT_TRUE(block.empty());
  EXPECT_EQ(0u, block.size());
  EXPECT_EQ(block.end(), block.find("foo"));
  EXPECT_EQ("", block.GetHeader("foo"));
  EXPECT_TRUE(block.end() == block.begin());

  // Should have no effect.
  block.erase("bar");
}

TEST(SpdyHeaderBlockTest, KeyMemoryReclaimedOnLookup) {
  SpdyHeaderBlock block;
  base::StringPiece copied_key1;
  {
    auto proxy1 = block["some key name"];
    copied_key1 = StringPieceProxyPeer::key(&proxy1);
  }
  base::StringPiece copied_key2;
  {
    auto proxy2 = block["some other key name"];
    copied_key2 = StringPieceProxyPeer::key(&proxy2);
  }
  // Because proxy1 was never used to modify the block, the memory used for the
  // key could be reclaimed and used for the second call to operator[].
  // Therefore, we expect the pointers of the two StringPieces to be equal.
  EXPECT_EQ(copied_key1.data(), copied_key2.data());

  {
    auto proxy1 = block["some key name"];
    block["some other key name"] = "some value";
  }
  // Nothing should blow up when proxy1 is destructed, and we should be able to
  // modify and access the SpdyHeaderBlock.
  block["key"] = "value";
  EXPECT_EQ(base::StringPiece("value"), block["key"]);
  EXPECT_EQ(base::StringPiece("some value"), block["some other key name"]);
  EXPECT_TRUE(block.find("some key name") == block.end());
}

// This test verifies that headers can be set in a variety of ways.
TEST(SpdyHeaderBlockTest, AddHeaders) {
  SpdyHeaderBlock block;
  block["foo"] = string(300, 'x');
  block["bar"] = "baz";
  block.ReplaceOrAppendHeader("qux", "qux1");
  block["qux"] = "qux2";
  block.insert(std::make_pair("key", "value"));

  EXPECT_EQ(Pair("foo", string(300, 'x')), *block.find("foo"));
  EXPECT_EQ("baz", block["bar"]);
  EXPECT_EQ("baz", block.GetHeader("bar"));
  string qux("qux");
  EXPECT_EQ("qux2", block[qux]);
  EXPECT_EQ("qux2", block.GetHeader(qux));
  EXPECT_EQ(Pair("key", "value"), *block.find("key"));

  block.erase("key");
  EXPECT_EQ(block.end(), block.find("key"));
  EXPECT_EQ("", block.GetHeader("key"));
}

// This test verifies that SpdyHeaderBlock can be copied using Clone().
TEST(SpdyHeaderBlockTest, CopyBlocks) {
  SpdyHeaderBlock block1;
  block1["foo"] = string(300, 'x');
  block1["bar"] = "baz";
  block1.ReplaceOrAppendHeader("qux", "qux1");

  SpdyHeaderBlock block2 = block1.Clone();
  SpdyHeaderBlock block3(block1.Clone());

  EXPECT_EQ(block1, block2);
  EXPECT_EQ(block1, block3);
}

TEST(SpdyHeaderBlockTest, ToNetLogParamAndBackAgain) {
  SpdyHeaderBlock headers;
  headers["A"] = "a";
  headers["B"] = "b";

  std::unique_ptr<base::Value> event_param(SpdyHeaderBlockNetLogCallback(
      &headers, NetLogCaptureMode::IncludeCookiesAndCredentials()));

  SpdyHeaderBlock headers2;
  ASSERT_TRUE(SpdyHeaderBlockFromNetLogParam(event_param.get(), &headers2));
  EXPECT_EQ(headers, headers2);
}

TEST(SpdyHeaderBlockTest, Equality) {
  // Test equality and inequality operators.
  SpdyHeaderBlock block1;
  block1["foo"] = "bar";

  SpdyHeaderBlock block2;
  block2["foo"] = "bar";

  SpdyHeaderBlock block3;
  block3["baz"] = "qux";

  EXPECT_EQ(block1, block2);
  EXPECT_NE(block1, block3);

  block2["baz"] = "qux";
  EXPECT_NE(block1, block2);
}

// Test that certain methods do not crash on moved-from instances.
TEST(SpdyHeaderBlockTest, MovedFromIsValid) {
  SpdyHeaderBlock block1;
  block1["foo"] = "bar";

  SpdyHeaderBlock block2(std::move(block1));
  EXPECT_THAT(block2, ElementsAre(Pair("foo", "bar")));

  block1.ReplaceOrAppendHeader("baz", "qux");

  SpdyHeaderBlock block3(std::move(block1));

  block1["foo"] = "bar";

  SpdyHeaderBlock block4(std::move(block1));

  block1.clear();
  EXPECT_TRUE(block1.empty());

  block1["foo"] = "bar";
  EXPECT_THAT(block1, ElementsAre(Pair("foo", "bar")));
}

// This test verifies that headers can be appended to no matter how they were
// added originally.
TEST(SpdyHeaderBlockTest, AppendHeaders) {
  SpdyHeaderBlock block;
  block["foo"] = "foo";
  block.AppendValueOrAddHeader("foo", "bar");
  EXPECT_EQ(Pair("foo", string("foo\0bar", 7)), *block.find("foo"));

  block.insert(std::make_pair("foo", "baz"));
  EXPECT_EQ("baz", block["foo"]);
  EXPECT_EQ(Pair("foo", "baz"), *block.find("foo"));

  // Try all four methods of adding an entry.
  block["cookie"] = "key1=value1";
  block.AppendValueOrAddHeader("h1", "h1v1");
  block.insert(std::make_pair("h2", "h2v1"));
  block.ReplaceOrAppendHeader("h3", "h3v1");

  block.AppendValueOrAddHeader("h3", "h3v2");
  block.AppendValueOrAddHeader("h2", "h2v2");
  block.AppendValueOrAddHeader("h1", "h1v2");
  block.AppendValueOrAddHeader("cookie", "key2=value2");

  block.ReplaceOrAppendHeader("h4", "h4v1");

  block.AppendValueOrAddHeader("cookie", "key3=value3");
  block.AppendValueOrAddHeader("h1", "h1v3");
  block.AppendValueOrAddHeader("h2", "h2v3");
  block.AppendValueOrAddHeader("h3", "h3v3");

  EXPECT_EQ("key1=value1; key2=value2; key3=value3", block["cookie"]);
  EXPECT_EQ("baz", block["foo"]);
  EXPECT_EQ(string("h1v1\0h1v2\0h1v3", 14), block["h1"]);
  EXPECT_EQ(string("h2v1\0h2v2\0h2v3", 14), block["h2"]);
  EXPECT_EQ(string("h3v1\0h3v2\0h3v3", 14), block["h3"]);
  EXPECT_EQ("h4v1", block["h4"]);
}

}  // namespace test
}  // namespace net
