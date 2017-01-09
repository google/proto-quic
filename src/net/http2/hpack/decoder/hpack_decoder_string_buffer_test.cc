// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/decoder/hpack_decoder_string_buffer.h"

// Tests of HpackDecoderStringBuffer.

#include <sstream>
#include <string>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "net/http2/tools/failure.h"
#include "net/spdy/spdy_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::AssertionResult;
using ::testing::AssertionSuccess;
using ::testing::HasSubstr;
using base::StringPiece;
using std::string;

namespace net {
namespace test {
namespace {

class HpackDecoderStringBufferTest : public ::testing::Test {
 protected:
  typedef HpackDecoderStringBuffer::State State;
  typedef HpackDecoderStringBuffer::Backing Backing;

  State state() const { return buf_.state_for_testing(); }
  Backing backing() const { return buf_.backing_for_testing(); }

  // We want to know that LOG(x) << buf_ will work in production should that
  // be needed, so we test that it outputs the expected values.
  AssertionResult VerifyLogHasSubstrs(std::initializer_list<string> strs) {
    VLOG(1) << buf_;
    std::ostringstream ss;
    buf_.OutputDebugStringTo(ss);
    string dbg_str(ss.str());
    for (const auto& expected : strs) {
      VERIFY_THAT(dbg_str, HasSubstr(expected));
    }
    return AssertionSuccess();
  }

  HpackDecoderStringBuffer buf_;
};

TEST_F(HpackDecoderStringBufferTest, SetStatic) {
  StringPiece data("static string");

  EXPECT_EQ(state(), State::RESET);
  EXPECT_TRUE(VerifyLogHasSubstrs({"state=RESET"}));

  buf_.Set(data, /*is_static*/ true);
  LOG(INFO) << buf_;
  EXPECT_EQ(state(), State::COMPLETE);
  EXPECT_EQ(backing(), Backing::STATIC);
  EXPECT_EQ(data, buf_.str());
  EXPECT_EQ(data.data(), buf_.str().data());
  EXPECT_TRUE(VerifyLogHasSubstrs(
      {"state=COMPLETE", "backing=STATIC", "value: static string"}));

  // The string is static, so BufferStringIfUnbuffered won't change anything.
  buf_.BufferStringIfUnbuffered();
  EXPECT_EQ(state(), State::COMPLETE);
  EXPECT_EQ(backing(), Backing::STATIC);
  EXPECT_EQ(data, buf_.str());
  EXPECT_EQ(data.data(), buf_.str().data());
  EXPECT_TRUE(VerifyLogHasSubstrs(
      {"state=COMPLETE", "backing=STATIC", "value: static string"}));
}

TEST_F(HpackDecoderStringBufferTest, PlainWhole) {
  StringPiece data("some text.");

  LOG(INFO) << buf_;
  EXPECT_EQ(state(), State::RESET);

  buf_.OnStart(/*huffman_encoded*/ false, data.size());
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::RESET);
  LOG(INFO) << buf_;

  EXPECT_TRUE(buf_.OnData(data.data(), data.size()));
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::UNBUFFERED);

  EXPECT_TRUE(buf_.OnEnd());
  EXPECT_EQ(state(), State::COMPLETE);
  EXPECT_EQ(backing(), Backing::UNBUFFERED);
  EXPECT_EQ(0u, buf_.BufferedLength());
  EXPECT_TRUE(VerifyLogHasSubstrs(
      {"state=COMPLETE", "backing=UNBUFFERED", "value: some text."}));

  // We expect that the string buffer points to the passed in StringPiece's
  // backing store.
  EXPECT_EQ(data.data(), buf_.str().data());

  // Now force it to buffer the string, after which it will still have the same
  // string value, but the backing store will be different.
  buf_.BufferStringIfUnbuffered();
  LOG(INFO) << buf_;
  EXPECT_EQ(backing(), Backing::BUFFERED);
  EXPECT_EQ(buf_.BufferedLength(), data.size());
  EXPECT_EQ(data, buf_.str());
  EXPECT_NE(data.data(), buf_.str().data());
  EXPECT_TRUE(VerifyLogHasSubstrs(
      {"state=COMPLETE", "backing=BUFFERED", "buffer: some text."}));
}

TEST_F(HpackDecoderStringBufferTest, PlainSplit) {
  StringPiece data("some text.");
  StringPiece part1 = data.substr(0, 1);
  StringPiece part2 = data.substr(1);

  EXPECT_EQ(state(), State::RESET);
  buf_.OnStart(/*huffman_encoded*/ false, data.size());
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::RESET);

  // OnData with only a part of the data, not the whole, so buf_ will buffer
  // the data.
  EXPECT_TRUE(buf_.OnData(part1.data(), part1.size()));
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::BUFFERED);
  EXPECT_EQ(buf_.BufferedLength(), part1.size());
  LOG(INFO) << buf_;

  EXPECT_TRUE(buf_.OnData(part2.data(), part2.size()));
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::BUFFERED);
  EXPECT_EQ(buf_.BufferedLength(), data.size());

  EXPECT_TRUE(buf_.OnEnd());
  EXPECT_EQ(state(), State::COMPLETE);
  EXPECT_EQ(backing(), Backing::BUFFERED);
  EXPECT_EQ(buf_.BufferedLength(), data.size());
  LOG(INFO) << buf_;

  StringPiece buffered = buf_.str();
  EXPECT_EQ(data, buffered);
  EXPECT_NE(data.data(), buffered.data());

  // The string is already buffered, so BufferStringIfUnbuffered should not make
  // any change.
  buf_.BufferStringIfUnbuffered();
  EXPECT_EQ(backing(), Backing::BUFFERED);
  EXPECT_EQ(buf_.BufferedLength(), data.size());
  EXPECT_EQ(buffered, buf_.str());
  EXPECT_EQ(buffered.data(), buf_.str().data());
}

TEST_F(HpackDecoderStringBufferTest, HuffmanWhole) {
  string encoded = a2b_hex("f1e3c2e5f23a6ba0ab90f4ff");
  StringPiece decoded("www.example.com");

  EXPECT_EQ(state(), State::RESET);
  buf_.OnStart(/*huffman_encoded*/ true, encoded.size());
  EXPECT_EQ(state(), State::COLLECTING);

  EXPECT_TRUE(buf_.OnData(encoded.data(), encoded.size()));
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::BUFFERED);

  EXPECT_TRUE(buf_.OnEnd());
  EXPECT_EQ(state(), State::COMPLETE);
  EXPECT_EQ(backing(), Backing::BUFFERED);
  EXPECT_EQ(buf_.BufferedLength(), decoded.size());
  EXPECT_EQ(decoded, buf_.str());
  EXPECT_TRUE(VerifyLogHasSubstrs(
      {"{state=COMPLETE", "backing=BUFFERED", "buffer: www.example.com}"}));

  string s = buf_.ReleaseString();
  EXPECT_EQ(s, decoded);
  EXPECT_EQ(state(), State::RESET);
}

TEST_F(HpackDecoderStringBufferTest, HuffmanSplit) {
  string encoded = a2b_hex("f1e3c2e5f23a6ba0ab90f4ff");
  string part1 = encoded.substr(0, 5);
  string part2 = encoded.substr(5);
  StringPiece decoded("www.example.com");

  EXPECT_EQ(state(), State::RESET);
  buf_.OnStart(/*huffman_encoded*/ true, encoded.size());
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::BUFFERED);
  EXPECT_EQ(0u, buf_.BufferedLength());
  LOG(INFO) << buf_;

  EXPECT_TRUE(buf_.OnData(part1.data(), part1.size()));
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::BUFFERED);
  EXPECT_GT(buf_.BufferedLength(), 0u);
  EXPECT_LT(buf_.BufferedLength(), decoded.size());
  LOG(INFO) << buf_;

  EXPECT_TRUE(buf_.OnData(part2.data(), part2.size()));
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::BUFFERED);
  EXPECT_EQ(buf_.BufferedLength(), decoded.size());
  LOG(INFO) << buf_;

  EXPECT_TRUE(buf_.OnEnd());
  EXPECT_EQ(state(), State::COMPLETE);
  EXPECT_EQ(backing(), Backing::BUFFERED);
  EXPECT_EQ(buf_.BufferedLength(), decoded.size());
  EXPECT_EQ(decoded, buf_.str());
  LOG(INFO) << buf_;

  buf_.Reset();
  EXPECT_EQ(state(), State::RESET);
  LOG(INFO) << buf_;
}

TEST_F(HpackDecoderStringBufferTest, InvalidHuffmanOnData) {
  // Explicitly encode the End-of-String symbol, a no-no.
  string encoded = a2b_hex("ffffffff");

  buf_.OnStart(/*huffman_encoded*/ true, encoded.size());
  EXPECT_EQ(state(), State::COLLECTING);

  EXPECT_FALSE(buf_.OnData(encoded.data(), encoded.size()));
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::BUFFERED);

  LOG(INFO) << buf_;
}

TEST_F(HpackDecoderStringBufferTest, InvalidHuffmanOnEnd) {
  // Last byte of string doesn't end with prefix of End-of-String symbol.
  string encoded = a2b_hex("00");

  buf_.OnStart(/*huffman_encoded*/ true, encoded.size());
  EXPECT_EQ(state(), State::COLLECTING);

  EXPECT_TRUE(buf_.OnData(encoded.data(), encoded.size()));
  EXPECT_EQ(state(), State::COLLECTING);
  EXPECT_EQ(backing(), Backing::BUFFERED);

  EXPECT_FALSE(buf_.OnEnd());
  LOG(INFO) << buf_;
}

// TODO(jamessynge): Add tests for ReleaseString().

}  // namespace
}  // namespace test
}  // namespace net
