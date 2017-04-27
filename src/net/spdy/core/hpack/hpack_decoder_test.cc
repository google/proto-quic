// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/core/hpack/hpack_decoder.h"

#include <map>

#include "base/logging.h"
#include "net/spdy/chromium/spdy_flags.h"
#include "net/spdy/core/hpack/hpack_encoder.h"
#include "net/spdy/core/hpack/hpack_input_stream.h"
#include "net/spdy/core/hpack/hpack_output_stream.h"
#include "net/spdy/core/spdy_protocol.h"
#include "net/spdy/core/spdy_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

class HpackDecoderPeer {
 public:
  explicit HpackDecoderPeer(HpackDecoder* decoder) : decoder_(decoder) {}

  void HandleHeaderRepresentation(SpdyStringPiece name, SpdyStringPiece value) {
    decoder_->HandleHeaderRepresentation(name, value);
  }
  bool DecodeNextName(HpackInputStream* in, SpdyStringPiece* out) {
    return decoder_->DecodeNextName(in, out);
  }
  HpackHeaderTable* header_table() { return &decoder_->header_table_; }

  bool DecodeNextStringLiteral(HpackInputStream* in,
                               bool is_header_key,
                               SpdyStringPiece* str) {
    return decoder_->DecodeNextStringLiteral(in, is_header_key, str);
  }

  const SpdyString& headers_block_buffer() const {
    return decoder_->headers_block_buffer_;
  }

 private:
  HpackDecoder* decoder_;
};

namespace {

using test::a2b_hex;

using testing::ElementsAre;
using testing::Pair;

class HpackDecoderTest : public ::testing::TestWithParam<bool> {
 protected:
  HpackDecoderTest() : decoder_(), decoder_peer_(&decoder_) {}

  void SetUp() override { handler_exists_ = GetParam(); }

  bool DecodeHeaderBlock(SpdyStringPiece str) {
    if (handler_exists_) {
      decoder_.HandleControlFrameHeadersStart(&handler_);
    }
    return decoder_.HandleControlFrameHeadersData(str.data(), str.size()) &&
           decoder_.HandleControlFrameHeadersComplete(nullptr);
  }

  bool HandleControlFrameHeadersData(SpdyStringPiece str) {
    return decoder_.HandleControlFrameHeadersData(str.data(), str.size());
  }

  bool HandleControlFrameHeadersComplete(size_t* size) {
    return decoder_.HandleControlFrameHeadersComplete(size);
  }

  const SpdyHeaderBlock& decoded_block() const {
    if (handler_exists_) {
      return handler_.decoded_block();
    } else {
      return decoder_.decoded_block();
    }
  }

  const SpdyHeaderBlock& DecodeBlockExpectingSuccess(SpdyStringPiece str) {
    EXPECT_TRUE(DecodeHeaderBlock(str));
    return decoded_block();
  }

  void expectEntry(size_t index,
                   size_t size,
                   const SpdyString& name,
                   const SpdyString& value) {
    const HpackEntry* entry = decoder_peer_.header_table()->GetByIndex(index);
    EXPECT_EQ(name, entry->name()) << "index " << index;
    EXPECT_EQ(value, entry->value());
    EXPECT_EQ(size, entry->Size());
    EXPECT_EQ(index, decoder_peer_.header_table()->IndexOf(entry));
  }

  HpackDecoder decoder_;
  test::HpackDecoderPeer decoder_peer_;
  TestHeadersHandler handler_;
  bool handler_exists_;
};

INSTANTIATE_TEST_CASE_P(WithAndWithoutHeadersHandler,
                        HpackDecoderTest,
                        ::testing::Bool());

TEST_P(HpackDecoderTest, AddHeaderDataWithHandleControlFrameHeadersData) {
  // The hpack decode buffer size is limited in size. This test verifies that
  // adding encoded data under that limit is accepted, and data that exceeds the
  // limit is rejected.
  const size_t kMaxBufferSizeBytes = 50;
  decoder_.set_max_decode_buffer_size_bytes(kMaxBufferSizeBytes);

  // Strings under threshold are concatenated in the buffer.
  SpdyString first_input;
  first_input.push_back(0x00);  // Literal name and value, unindexed
  first_input.push_back(0x7f);  // Name length = 127
  ASSERT_EQ(2u, first_input.size());
  EXPECT_TRUE(decoder_.HandleControlFrameHeadersData(first_input.data(),
                                                     first_input.size()));
  // Further 38 bytes to make 40 total buffered bytes.
  SpdyString second_input = SpdyString(38, 'x');
  EXPECT_TRUE(decoder_.HandleControlFrameHeadersData(second_input.data(),
                                                     second_input.size()));
  // A string which would push the buffer over the threshold is refused.
  const int kThirdInputSize =
      kMaxBufferSizeBytes - (first_input.size() + second_input.size()) + 1;
  SpdyString third_input = SpdyString(kThirdInputSize, 'y');
  ASSERT_GT(first_input.size() + second_input.size() + third_input.size(),
            kMaxBufferSizeBytes);
  EXPECT_FALSE(decoder_.HandleControlFrameHeadersData(third_input.data(),
                                                      third_input.size()));

  SpdyString expected(first_input);
  expected.append(second_input);
  EXPECT_EQ(expected, decoder_peer_.headers_block_buffer());
}

// Decode with incomplete data in buffer.
TEST_P(HpackDecoderTest, DecodeWithIncompleteData) {
  // No need to wait for more data.
  EXPECT_TRUE(HandleControlFrameHeadersData("\x82\x85\x82"));
  EXPECT_EQ("", decoder_peer_.headers_block_buffer());

  // Need to wait for more data.
  EXPECT_TRUE(
      HandleControlFrameHeadersData("\x40\x03goo"
                                    "\x03gar\xbe\x40\x04spam"));
  EXPECT_EQ("\x40\x04spam", decoder_peer_.headers_block_buffer());

  // Add the needed data.
  EXPECT_TRUE(HandleControlFrameHeadersData("\x04gggs"));
  EXPECT_EQ("", decoder_peer_.headers_block_buffer());

  size_t size = 0;
  EXPECT_TRUE(HandleControlFrameHeadersComplete(&size));
  EXPECT_EQ(24u, size);
}

TEST_P(HpackDecoderTest, HandleHeaderRepresentation) {
  if (handler_exists_) {
    decoder_.HandleControlFrameHeadersStart(&handler_);
  }

  // All cookie crumbs are joined.
  decoder_peer_.HandleHeaderRepresentation("cookie", " part 1");
  decoder_peer_.HandleHeaderRepresentation("cookie", "part 2 ");
  decoder_peer_.HandleHeaderRepresentation("cookie", "part3");

  // Already-delimited headers are passed through.
  decoder_peer_.HandleHeaderRepresentation("passed-through",
                                           SpdyString("foo\0baz", 7));

  // Other headers are joined on \0. Case matters.
  decoder_peer_.HandleHeaderRepresentation("joined", "not joined");
  decoder_peer_.HandleHeaderRepresentation("joineD", "value 1");
  decoder_peer_.HandleHeaderRepresentation("joineD", "value 2");

  // Empty headers remain empty.
  decoder_peer_.HandleHeaderRepresentation("empty", "");

  // Joined empty headers work as expected.
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "");
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "foo");
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "");
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "");

  // Non-contiguous cookie crumb.
  decoder_peer_.HandleHeaderRepresentation("cookie", " fin!");

  // Finish and emit all headers.
  decoder_.HandleControlFrameHeadersComplete(nullptr);

  // Resulting decoded headers are in the same order as input.
  EXPECT_THAT(
      decoded_block(),
      ElementsAre(Pair("cookie", " part 1; part 2 ; part3;  fin!"),
                  Pair("passed-through", SpdyStringPiece("foo\0baz", 7)),
                  Pair("joined", "not joined"),
                  Pair("joineD", SpdyStringPiece("value 1\0value 2", 15)),
                  Pair("empty", ""),
                  Pair("empty-joined", SpdyStringPiece("\0foo\0\0", 6))));
}

// Decoding an encoded name with a valid string literal should work.
TEST_P(HpackDecoderTest, DecodeNextNameLiteral) {
  HpackInputStream input_stream(SpdyStringPiece("\x00\x04name", 6));

  SpdyStringPiece string_piece;
  EXPECT_TRUE(decoder_peer_.DecodeNextName(&input_stream, &string_piece));
  EXPECT_EQ("name", string_piece);
  EXPECT_FALSE(input_stream.HasMoreData());
  EXPECT_FALSE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(6u, input_stream.ParsedBytes());
}

// Decoding an encoded name with an incomplete string literal.
TEST_P(HpackDecoderTest, DecodeNextNameLiteralWithIncompleteHeader) {
  HpackInputStream input_stream(SpdyStringPiece("\x00\x04name\x00\x02g", 9));

  SpdyStringPiece string_piece;
  EXPECT_TRUE(decoder_peer_.DecodeNextName(&input_stream, &string_piece));
  EXPECT_FALSE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(6u, input_stream.ParsedBytes());

  EXPECT_FALSE(decoder_peer_.DecodeNextName(&input_stream, &string_piece));
  EXPECT_TRUE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(8u, input_stream.ParsedBytes());
}

TEST_P(HpackDecoderTest, DecodeNextNameLiteralWithHuffmanEncoding) {
  SpdyString input = a2b_hex("008825a849e95ba97d7f");
  HpackInputStream input_stream(input);

  SpdyStringPiece string_piece;
  EXPECT_TRUE(decoder_peer_.DecodeNextName(&input_stream, &string_piece));
  EXPECT_EQ("custom-key", string_piece);
  EXPECT_FALSE(input_stream.HasMoreData());
  EXPECT_FALSE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(input.size(), input_stream.ParsedBytes());
}

// Decode with incomplete huffman encoding.
TEST_P(HpackDecoderTest, DecodeNextNameLiteralWithIncompleteHuffmanEncoding) {
  // CHECK(huffman_table_.Initialize(kHpackHuffmanCode,
  //                                 arraysize(kHpackHuffmanCode)));
  // Put two copies of the same huffman encoding into input.
  SpdyString input = a2b_hex("008825a849e95ba97d7f008825a849e95ba97d7f");
  input.resize(input.size() - 1);  // Remove the last byte.
  HpackInputStream input_stream(input);

  SpdyStringPiece string_piece;
  EXPECT_TRUE(decoder_peer_.DecodeNextName(&input_stream, &string_piece));
  EXPECT_FALSE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(10u, input_stream.ParsedBytes());

  EXPECT_FALSE(decoder_peer_.DecodeNextName(&input_stream, &string_piece));
  EXPECT_TRUE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(12u, input_stream.ParsedBytes());
}

// Decoding an encoded name with a valid index should work.
TEST_P(HpackDecoderTest, DecodeNextNameIndexed) {
  HpackInputStream input_stream("\x01");

  SpdyStringPiece string_piece;
  EXPECT_TRUE(decoder_peer_.DecodeNextName(&input_stream, &string_piece));
  EXPECT_EQ(":authority", string_piece);
  EXPECT_FALSE(input_stream.HasMoreData());
  EXPECT_FALSE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(1u, input_stream.ParsedBytes());
}

// Decoding an encoded name with an invalid index should fail.
TEST_P(HpackDecoderTest, DecodeNextNameInvalidIndex) {
  // One more than the number of static table entries.
  HpackInputStream input_stream("\x3e");

  SpdyStringPiece string_piece;
  EXPECT_FALSE(decoder_peer_.DecodeNextName(&input_stream, &string_piece));
  EXPECT_FALSE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(1u, input_stream.ParsedBytes());
}

// Decoding indexed static table field should work.
TEST_P(HpackDecoderTest, IndexedHeaderStatic) {
  // Reference static table entries #2 and #5.
  const SpdyHeaderBlock& header_set1 = DecodeBlockExpectingSuccess("\x82\x85");
  SpdyHeaderBlock expected_header_set1;
  expected_header_set1[":method"] = "GET";
  expected_header_set1[":path"] = "/index.html";
  EXPECT_EQ(expected_header_set1, header_set1);

  // Reference static table entry #2.
  const SpdyHeaderBlock& header_set2 = DecodeBlockExpectingSuccess("\x82");
  SpdyHeaderBlock expected_header_set2;
  expected_header_set2[":method"] = "GET";
  EXPECT_EQ(expected_header_set2, header_set2);
}

TEST_P(HpackDecoderTest, IndexedHeaderDynamic) {
  // First header block: add an entry to header table.
  const SpdyHeaderBlock& header_set1 = DecodeBlockExpectingSuccess(
      "\x40\x03"
      "foo"
      "\x03"
      "bar");
  SpdyHeaderBlock expected_header_set1;
  expected_header_set1["foo"] = "bar";
  EXPECT_EQ(expected_header_set1, header_set1);

  // Second header block: add another entry to header table.
  const SpdyHeaderBlock& header_set2 = DecodeBlockExpectingSuccess(
      "\xbe\x40\x04"
      "spam"
      "\x04"
      "eggs");
  SpdyHeaderBlock expected_header_set2;
  expected_header_set2["foo"] = "bar";
  expected_header_set2["spam"] = "eggs";
  EXPECT_EQ(expected_header_set2, header_set2);

  // Third header block: refer to most recently added entry.
  const SpdyHeaderBlock& header_set3 = DecodeBlockExpectingSuccess("\xbe");
  SpdyHeaderBlock expected_header_set3;
  expected_header_set3["spam"] = "eggs";
  EXPECT_EQ(expected_header_set3, header_set3);
}

// Test a too-large indexed header.
TEST_P(HpackDecoderTest, InvalidIndexedHeader) {
  // High-bit set, and a prefix of one more than the number of static entries.
  EXPECT_FALSE(DecodeHeaderBlock(SpdyStringPiece("\xbe", 1)));
}

TEST_P(HpackDecoderTest, ContextUpdateMaximumSize) {
  EXPECT_EQ(kDefaultHeaderTableSizeSetting,
            decoder_peer_.header_table()->max_size());
  SpdyString input;
  {
    // Maximum-size update with size 126. Succeeds.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(126);

    output_stream.TakeString(&input);
    EXPECT_TRUE(DecodeHeaderBlock(SpdyStringPiece(input)));
    EXPECT_EQ(126u, decoder_peer_.header_table()->max_size());
  }
  {
    // Maximum-size update with kDefaultHeaderTableSizeSetting. Succeeds.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(kDefaultHeaderTableSizeSetting);

    output_stream.TakeString(&input);
    EXPECT_TRUE(DecodeHeaderBlock(SpdyStringPiece(input)));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table()->max_size());
  }
  {
    // Maximum-size update with kDefaultHeaderTableSizeSetting + 1. Fails.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(kDefaultHeaderTableSizeSetting + 1);

    output_stream.TakeString(&input);
    EXPECT_FALSE(DecodeHeaderBlock(SpdyStringPiece(input)));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table()->max_size());
  }
}

// Two HeaderTableSizeUpdates may appear at the beginning of the block
TEST_P(HpackDecoderTest, TwoTableSizeUpdates) {
  SpdyString input;
  {
    // Should accept two table size updates, update to second one
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(0);
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(122);

    output_stream.TakeString(&input);
    EXPECT_TRUE(DecodeHeaderBlock(SpdyStringPiece(input)));
    EXPECT_EQ(122u, decoder_peer_.header_table()->max_size());
  }
}

// Three HeaderTableSizeUpdates should result in an error
TEST_P(HpackDecoderTest, ThreeTableSizeUpdatesError) {
  SpdyString input;
  {
    // Should reject three table size updates, update to second one
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(5);
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(10);
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(15);

    output_stream.TakeString(&input);

    EXPECT_FALSE(DecodeHeaderBlock(SpdyStringPiece(input)));
    EXPECT_EQ(10u, decoder_peer_.header_table()->max_size());
  }
}

// HeaderTableSizeUpdates may only appear at the beginning of the block
// Any other updates should result in an error
TEST_P(HpackDecoderTest, TableSizeUpdateSecondError) {
  SpdyString input;
  {
    // Should reject a table size update appearing after a different entry
    // The table size should remain as the default
    HpackOutputStream output_stream;
    output_stream.AppendBytes("\x82\x85");
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(123);

    output_stream.TakeString(&input);

    EXPECT_FALSE(DecodeHeaderBlock(SpdyStringPiece(input)));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table()->max_size());
  }
}

// HeaderTableSizeUpdates may only appear at the beginning of the block
// Any other updates should result in an error
TEST_P(HpackDecoderTest, TableSizeUpdateFirstThirdError) {
  SpdyString input;
  {
    // Should reject the second table size update
    // if a different entry appears after the first update
    // The table size should update to the first but not the second
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(60);
    output_stream.AppendBytes("\x82\x85");
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(125);

    output_stream.TakeString(&input);

    EXPECT_FALSE(DecodeHeaderBlock(SpdyStringPiece(input)));
    EXPECT_EQ(60u, decoder_peer_.header_table()->max_size());
  }
}

// Decoding two valid encoded literal headers with no indexing should
// work.
TEST_P(HpackDecoderTest, LiteralHeaderNoIndexing) {
  // First header with indexed name, second header with string literal
  // name.
  const char input[] = "\x04\x0c/sample/path\x00\x06:path2\x0e/sample/path/2";
  const SpdyHeaderBlock& header_set =
      DecodeBlockExpectingSuccess(SpdyStringPiece(input, arraysize(input) - 1));

  SpdyHeaderBlock expected_header_set;
  expected_header_set[":path"] = "/sample/path";
  expected_header_set[":path2"] = "/sample/path/2";
  EXPECT_EQ(expected_header_set, header_set);
}

// Decoding two valid encoded literal headers with incremental
// indexing and string literal names should work.
TEST_P(HpackDecoderTest, LiteralHeaderIncrementalIndexing) {
  const char input[] = "\x44\x0c/sample/path\x40\x06:path2\x0e/sample/path/2";
  const SpdyHeaderBlock& header_set =
      DecodeBlockExpectingSuccess(SpdyStringPiece(input, arraysize(input) - 1));

  SpdyHeaderBlock expected_header_set;
  expected_header_set[":path"] = "/sample/path";
  expected_header_set[":path2"] = "/sample/path/2";
  EXPECT_EQ(expected_header_set, header_set);
}

TEST_P(HpackDecoderTest, LiteralHeaderWithIndexingInvalidNameIndex) {
  decoder_.ApplyHeaderTableSizeSetting(0);

  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(SpdyStringPiece("\x7d\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(SpdyStringPiece("\x7e\x03ooo")));
}

TEST_P(HpackDecoderTest, LiteralHeaderNoIndexingInvalidNameIndex) {
  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(SpdyStringPiece("\x0f\x2e\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(SpdyStringPiece("\x0f\x2f\x03ooo")));
}

TEST_P(HpackDecoderTest, LiteralHeaderNeverIndexedInvalidNameIndex) {
  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(SpdyStringPiece("\x1f\x2e\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(SpdyStringPiece("\x1f\x2f\x03ooo")));
}

// Decode with incomplete string literal.
TEST_P(HpackDecoderTest, StringLiteralIncomplete) {
  const char input[] = "\x0c/sample/path\x06:path2\x0e/sample/path/";
  HpackInputStream input_stream(input);
  SpdyStringPiece str;
  EXPECT_TRUE(
      decoder_peer_.DecodeNextStringLiteral(&input_stream, false, &str));
  EXPECT_FALSE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(13u, input_stream.ParsedBytes());

  EXPECT_TRUE(
      decoder_peer_.DecodeNextStringLiteral(&input_stream, false, &str));
  EXPECT_FALSE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(20u, input_stream.ParsedBytes());

  EXPECT_FALSE(
      decoder_peer_.DecodeNextStringLiteral(&input_stream, false, &str));
  EXPECT_TRUE(input_stream.NeedMoreData());
  input_stream.MarkCurrentPosition();
  EXPECT_EQ(21u, input_stream.ParsedBytes());
}

// Round-tripping the header set from RFC 7541 C.3.1 should work.
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.3.1
TEST_P(HpackDecoderTest, BasicC31) {
  HpackEncoder encoder(ObtainHpackHuffmanTable());

  SpdyHeaderBlock expected_header_set;
  expected_header_set[":method"] = "GET";
  expected_header_set[":scheme"] = "http";
  expected_header_set[":path"] = "/";
  expected_header_set[":authority"] = "www.example.com";

  SpdyString encoded_header_set;
  EXPECT_TRUE(
      encoder.EncodeHeaderSet(expected_header_set, &encoded_header_set));

  EXPECT_TRUE(DecodeHeaderBlock(encoded_header_set));
  EXPECT_EQ(expected_header_set, decoded_block());
}

// RFC 7541, Section C.4: Request Examples with Huffman Coding
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.4
TEST_P(HpackDecoderTest, SectionC4RequestHuffmanExamples) {
  // 82                                      | == Indexed - Add ==
  //                                         |   idx = 2
  //                                         | -> :method: GET
  // 86                                      | == Indexed - Add ==
  //                                         |   idx = 6
  //                                         | -> :scheme: http
  // 84                                      | == Indexed - Add ==
  //                                         |   idx = 4
  //                                         | -> :path: /
  // 41                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 1)
  //                                         |     :authority
  // 8c                                      |   Literal value (len = 15)
  //                                         |     Huffman encoded:
  // f1e3 c2e5 f23a 6ba0 ab90 f4ff           | .....:k.....
  //                                         |     Decoded:
  //                                         | www.example.com
  //                                         | -> :authority: www.example.com
  SpdyString first = a2b_hex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
  const SpdyHeaderBlock& first_header_set = DecodeBlockExpectingSuccess(first);

  EXPECT_THAT(
      first_header_set,
      ElementsAre(Pair(":method", "GET"), Pair(":scheme", "http"),
                  Pair(":path", "/"), Pair(":authority", "www.example.com")));

  expectEntry(62, 57, ":authority", "www.example.com");
  EXPECT_EQ(57u, decoder_peer_.header_table()->size());

  // 82                                      | == Indexed - Add ==
  //                                         |   idx = 2
  //                                         | -> :method: GET
  // 86                                      | == Indexed - Add ==
  //                                         |   idx = 6
  //                                         | -> :scheme: http
  // 84                                      | == Indexed - Add ==
  //                                         |   idx = 4
  //                                         | -> :path: /
  // be                                      | == Indexed - Add ==
  //                                         |   idx = 62
  //                                         | -> :authority: www.example.com
  // 58                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 24)
  //                                         |     cache-control
  // 86                                      |   Literal value (len = 8)
  //                                         |     Huffman encoded:
  // a8eb 1064 9cbf                          | ...d..
  //                                         |     Decoded:
  //                                         | no-cache
  //                                         | -> cache-control: no-cache

  SpdyString second = a2b_hex("828684be5886a8eb10649cbf");
  const SpdyHeaderBlock& second_header_set =
      DecodeBlockExpectingSuccess(second);

  EXPECT_THAT(
      second_header_set,
      ElementsAre(Pair(":method", "GET"), Pair(":scheme", "http"),
                  Pair(":path", "/"), Pair(":authority", "www.example.com"),
                  Pair("cache-control", "no-cache")));

  expectEntry(62, 53, "cache-control", "no-cache");
  expectEntry(63, 57, ":authority", "www.example.com");
  EXPECT_EQ(110u, decoder_peer_.header_table()->size());

  // 82                                      | == Indexed - Add ==
  //                                         |   idx = 2
  //                                         | -> :method: GET
  // 87                                      | == Indexed - Add ==
  //                                         |   idx = 7
  //                                         | -> :scheme: https
  // 85                                      | == Indexed - Add ==
  //                                         |   idx = 5
  //                                         | -> :path: /index.html
  // bf                                      | == Indexed - Add ==
  //                                         |   idx = 63
  //                                         | -> :authority: www.example.com
  // 40                                      | == Literal indexed ==
  // 88                                      |   Literal name (len = 10)
  //                                         |     Huffman encoded:
  // 25a8 49e9 5ba9 7d7f                     | %.I.[.}.
  //                                         |     Decoded:
  //                                         | custom-key
  // 89                                      |   Literal value (len = 12)
  //                                         |     Huffman encoded:
  // 25a8 49e9 5bb8 e8b4 bf                  | %.I.[....
  //                                         |     Decoded:
  //                                         | custom-value
  //                                         | -> custom-key: custom-value
  SpdyString third = a2b_hex(
      "828785bf408825a849e95ba97d7f89"
      "25a849e95bb8e8b4bf");
  const SpdyHeaderBlock& third_header_set = DecodeBlockExpectingSuccess(third);

  EXPECT_THAT(third_header_set,
              ElementsAre(Pair(":method", "GET"), Pair(":scheme", "https"),
                          Pair(":path", "/index.html"),
                          Pair(":authority", "www.example.com"),
                          Pair("custom-key", "custom-value")));

  expectEntry(62, 54, "custom-key", "custom-value");
  expectEntry(63, 53, "cache-control", "no-cache");
  expectEntry(64, 57, ":authority", "www.example.com");
  EXPECT_EQ(164u, decoder_peer_.header_table()->size());
}

// RFC 7541, Section C.6: Response Examples with Huffman Coding
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.6
TEST_P(HpackDecoderTest, SectionC6ResponseHuffmanExamples) {
  decoder_.ApplyHeaderTableSizeSetting(256);

  // 48                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 8)
  //                                         |     :status
  // 82                                      |   Literal value (len = 3)
  //                                         |     Huffman encoded:
  // 6402                                    | d.
  //                                         |     Decoded:
  //                                         | 302
  //                                         | -> :status: 302
  // 58                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 24)
  //                                         |     cache-control
  // 85                                      |   Literal value (len = 7)
  //                                         |     Huffman encoded:
  // aec3 771a 4b                            | ..w.K
  //                                         |     Decoded:
  //                                         | private
  //                                         | -> cache-control: private
  // 61                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 33)
  //                                         |     date
  // 96                                      |   Literal value (len = 29)
  //                                         |     Huffman encoded:
  // d07a be94 1054 d444 a820 0595 040b 8166 | .z...T.D. .....f
  // e082 a62d 1bff                          | ...-..
  //                                         |     Decoded:
  //                                         | Mon, 21 Oct 2013 20:13:21
  //                                         | GMT
  //                                         | -> date: Mon, 21 Oct 2013
  //                                         |   20:13:21 GMT
  // 6e                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 46)
  //                                         |     location
  // 91                                      |   Literal value (len = 23)
  //                                         |     Huffman encoded:
  // 9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 | .)...c.........C
  // d3                                      | .
  //                                         |     Decoded:
  //                                         | https://www.example.com
  //                                         | -> location: https://www.e
  //                                         |    xample.com

  SpdyString first = a2b_hex(
      "488264025885aec3771a4b6196d07abe"
      "941054d444a8200595040b8166e082a6"
      "2d1bff6e919d29ad171863c78f0b97c8"
      "e9ae82ae43d3");
  const SpdyHeaderBlock& first_header_set = DecodeBlockExpectingSuccess(first);

  EXPECT_THAT(
      first_header_set,
      ElementsAre(Pair(":status", "302"), Pair("cache-control", "private"),
                  Pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                  Pair("location", "https://www.example.com")));

  expectEntry(62, 63, "location", "https://www.example.com");
  expectEntry(63, 65, "date", "Mon, 21 Oct 2013 20:13:21 GMT");
  expectEntry(64, 52, "cache-control", "private");
  expectEntry(65, 42, ":status", "302");
  EXPECT_EQ(222u, decoder_peer_.header_table()->size());

  // 48                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 8)
  //                                         |     :status
  // 83                                      |   Literal value (len = 3)
  //                                         |     Huffman encoded:
  // 640e ff                                 | d..
  //                                         |     Decoded:
  //                                         | 307
  //                                         | - evict: :status: 302
  //                                         | -> :status: 307
  // c1                                      | == Indexed - Add ==
  //                                         |   idx = 65
  //                                         | -> cache-control: private
  // c0                                      | == Indexed - Add ==
  //                                         |   idx = 64
  //                                         | -> date: Mon, 21 Oct 2013
  //                                         |   20:13:21 GMT
  // bf                                      | == Indexed - Add ==
  //                                         |   idx = 63
  //                                         | -> location:
  //                                         |   https://www.example.com
  SpdyString second = a2b_hex("4883640effc1c0bf");
  const SpdyHeaderBlock& second_header_set =
      DecodeBlockExpectingSuccess(second);

  EXPECT_THAT(
      second_header_set,
      ElementsAre(Pair(":status", "307"), Pair("cache-control", "private"),
                  Pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                  Pair("location", "https://www.example.com")));

  expectEntry(62, 42, ":status", "307");
  expectEntry(63, 63, "location", "https://www.example.com");
  expectEntry(64, 65, "date", "Mon, 21 Oct 2013 20:13:21 GMT");
  expectEntry(65, 52, "cache-control", "private");
  EXPECT_EQ(222u, decoder_peer_.header_table()->size());

  // 88                                      | == Indexed - Add ==
  //                                         |   idx = 8
  //                                         | -> :status: 200
  // c1                                      | == Indexed - Add ==
  //                                         |   idx = 65
  //                                         | -> cache-control: private
  // 61                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 33)
  //                                         |     date
  // 96                                      |   Literal value (len = 22)
  //                                         |     Huffman encoded:
  // d07a be94 1054 d444 a820 0595 040b 8166 | .z...T.D. .....f
  // e084 a62d 1bff                          | ...-..
  //                                         |     Decoded:
  //                                         | Mon, 21 Oct 2013 20:13:22
  //                                         | GMT
  //                                         | - evict: cache-control:
  //                                         |   private
  //                                         | -> date: Mon, 21 Oct 2013
  //                                         |   20:13:22 GMT
  // c0                                      | == Indexed - Add ==
  //                                         |   idx = 64
  //                                         | -> location:
  //                                         |    https://www.example.com
  // 5a                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 26)
  //                                         |     content-encoding
  // 83                                      |   Literal value (len = 3)
  //                                         |     Huffman encoded:
  // 9bd9 ab                                 | ...
  //                                         |     Decoded:
  //                                         | gzip
  //                                         | - evict: date: Mon, 21 Oct
  //                                         |    2013 20:13:21 GMT
  //                                         | -> content-encoding: gzip
  // 77                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 55)
  //                                         |     set-cookie
  // ad                                      |   Literal value (len = 45)
  //                                         |     Huffman encoded:
  // 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 | .........5...[9`
  // d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 | ..'..6r..'..)...
  // 3160 65c0 03ed 4ee5 b106 3d50 07        | 1`e...N...=P.
  //                                         |     Decoded:
  //                                         | foo=ASDJKHQKBZXOQWEOPIUAXQ
  //                                         | WEOIU; max-age=3600; versi
  //                                         | on=1
  //                                         | - evict: location:
  //                                         |   https://www.example.com
  //                                         | - evict: :status: 307
  //                                         | -> set-cookie: foo=ASDJKHQ
  //                                         |   KBZXOQWEOPIUAXQWEOIU;
  //                                         |   max-age=3600; version=1
  SpdyString third = a2b_hex(
      "88c16196d07abe941054d444a8200595"
      "040b8166e084a62d1bffc05a839bd9ab"
      "77ad94e7821dd7f2e6c7b335dfdfcd5b"
      "3960d5af27087f3672c1ab270fb5291f"
      "9587316065c003ed4ee5b1063d5007");
  const SpdyHeaderBlock& third_header_set = DecodeBlockExpectingSuccess(third);

  EXPECT_THAT(
      third_header_set,
      ElementsAre(Pair(":status", "200"), Pair("cache-control", "private"),
                  Pair("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                  Pair("location", "https://www.example.com"),
                  Pair("content-encoding", "gzip"),
                  Pair("set-cookie",
                       "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU;"
                       " max-age=3600; version=1")));

  expectEntry(62, 98, "set-cookie",
              "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU;"
              " max-age=3600; version=1");
  expectEntry(63, 52, "content-encoding", "gzip");
  expectEntry(64, 65, "date", "Mon, 21 Oct 2013 20:13:22 GMT");
  EXPECT_EQ(215u, decoder_peer_.header_table()->size());
}

}  // namespace
}  // namespace test
}  // namespace net
