// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack/hpack_decoder2.h"

// Tests of HpackDecoder2.

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "net/http2/hpack/tools/hpack_block_builder.h"
#include "net/http2/tools/http2_random.h"
#include "net/spdy/hpack/hpack_encoder.h"
#include "net/spdy/hpack/hpack_entry.h"
#include "net/spdy/hpack/hpack_huffman_table.h"
#include "net/spdy/hpack/hpack_output_stream.h"
#include "net/spdy/spdy_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::string;

namespace net {
namespace test {

class HpackDecoder2Peer {
 public:
  explicit HpackDecoder2Peer(HpackDecoder2* decoder) : decoder_(decoder) {}

  void HandleHeaderRepresentation(StringPiece name, StringPiece value) {
    decoder_->HandleHeaderRepresentation(name, value);
  }
  HpackHeaderTable* header_table() { return &decoder_->header_table_; }

 private:
  HpackDecoder2* decoder_;
};

namespace {

using testing::ElementsAre;
using testing::Pair;

// Is HandleControlFrameHeadersStart to be called, and with what value?
enum StartChoice { START_WITH_HANDLER, START_WITHOUT_HANDLER, NO_START };

class HpackDecoder2Test
    : public ::testing::TestWithParam<std::tuple<StartChoice, bool>> {
 protected:
  HpackDecoder2Test() : decoder_(), decoder_peer_(&decoder_) {}

  void SetUp() override {
    std::tie(start_choice_, randomly_split_input_buffer_) = GetParam();
  }

  void HandleControlFrameHeadersStart() {
    switch (start_choice_) {
      case START_WITH_HANDLER:
        decoder_.HandleControlFrameHeadersStart(&handler_);
        break;
      case START_WITHOUT_HANDLER:
        decoder_.HandleControlFrameHeadersStart(nullptr);
        break;
      case NO_START:
        break;
    }
  }

  bool HandleControlFrameHeadersData(StringPiece str) {
    return decoder_.HandleControlFrameHeadersData(str.data(), str.size());
  }

  bool HandleControlFrameHeadersComplete(size_t* size) {
    return decoder_.HandleControlFrameHeadersComplete(size);
  }

  bool DecodeHeaderBlock(StringPiece str) {
    // Don't call this again if HandleControlFrameHeadersData failed previously.
    EXPECT_FALSE(decode_has_failed_);
    HandleControlFrameHeadersStart();
    if (randomly_split_input_buffer_) {
      do {
        // Decode some fragment of the remaining bytes.
        size_t bytes = str.length();
        if (!str.empty()) {
          bytes = (random_.Rand8() % str.length()) + 1;
        }
        EXPECT_LE(bytes, str.length());
        if (!HandleControlFrameHeadersData(str.substr(0, bytes))) {
          decode_has_failed_ = true;
          return false;
        }
        str.remove_prefix(bytes);
      } while (!str.empty());
    } else if (!HandleControlFrameHeadersData(str)) {
      decode_has_failed_ = true;
      return false;
    }
    if (!HandleControlFrameHeadersComplete(nullptr)) {
      decode_has_failed_ = true;
      return false;
    }
    return true;
  }

  const SpdyHeaderBlock& decoded_block() const {
    if (start_choice_ == START_WITH_HANDLER) {
      return handler_.decoded_block();
    } else {
      return decoder_.decoded_block();
    }
  }

  const SpdyHeaderBlock& DecodeBlockExpectingSuccess(StringPiece str) {
    EXPECT_TRUE(DecodeHeaderBlock(str));
    return decoded_block();
  }

  void expectEntry(size_t index,
                   size_t size,
                   const string& name,
                   const string& value) {
    const HpackEntry* entry = decoder_peer_.header_table()->GetByIndex(index);
    EXPECT_EQ(name, entry->name()) << "index " << index;
    EXPECT_EQ(value, entry->value());
    EXPECT_EQ(size, entry->Size());
    EXPECT_EQ(index, decoder_peer_.header_table()->IndexOf(entry));
  }

  SpdyHeaderBlock MakeHeaderBlock(
      const std::vector<std::pair<string, string>>& headers) {
    SpdyHeaderBlock result;
    for (const auto& kv : headers) {
      result.AppendValueOrAddHeader(kv.first, kv.second);
    }
    return result;
  }

  Http2Random random_;
  HpackDecoder2 decoder_;
  test::HpackDecoder2Peer decoder_peer_;
  TestHeadersHandler handler_;
  StartChoice start_choice_;
  bool randomly_split_input_buffer_;
  bool decode_has_failed_ = false;
};

INSTANTIATE_TEST_CASE_P(
    StartChoiceAndRandomlySplitChoice,
    HpackDecoder2Test,
    ::testing::Combine(
        ::testing::Values(START_WITH_HANDLER, START_WITHOUT_HANDLER, NO_START),
        ::testing::Bool()));

TEST_P(HpackDecoder2Test, AddHeaderDataWithHandleControlFrameHeadersData) {
  // The hpack decode buffer size is limited in size. This test verifies that
  // adding encoded data under that limit is accepted, and data that exceeds the
  // limit is rejected.
  HandleControlFrameHeadersStart();
  const size_t kMaxBufferSizeBytes = 50;
  const string a_value = string(49, 'x');
  decoder_.set_max_decode_buffer_size_bytes(kMaxBufferSizeBytes);
  {
    HpackBlockBuilder hbb;
    hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                  false, "a", false, a_value);
    const auto& s = hbb.buffer();
    EXPECT_TRUE(decoder_.HandleControlFrameHeadersData(s.data(), s.size()));
  }
  {
    HpackBlockBuilder hbb;
    hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                  false, "b", false, string(51, 'x'));
    const auto& s = hbb.buffer();
    EXPECT_FALSE(decoder_.HandleControlFrameHeadersData(s.data(), s.size()));
  }

  SpdyHeaderBlock expected_block = MakeHeaderBlock({{"a", a_value}});
  EXPECT_EQ(expected_block, decoded_block());
}

TEST_P(HpackDecoder2Test, NameTooLong) {
  // Verify that a name longer than the allowed size generates an error.
  const size_t kMaxBufferSizeBytes = 50;
  const string name = string(2 * kMaxBufferSizeBytes, 'x');
  const string value = "abc";

  decoder_.set_max_decode_buffer_size_bytes(kMaxBufferSizeBytes);

  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                false, name, false, value);

  const size_t fragment_size = (3 * kMaxBufferSizeBytes) / 2;
  const string fragment = hbb.buffer().substr(0, fragment_size);

  HandleControlFrameHeadersStart();
  EXPECT_FALSE(HandleControlFrameHeadersData(fragment));
}

TEST_P(HpackDecoder2Test, HeaderTooLongToBuffer) {
  // Verify that a header longer than the allowed size generates an error if
  // it isn't all in one input buffer.
  const string name = "some-key";
  const string value = "some-value";
  const size_t kMaxBufferSizeBytes = name.size() + value.size() - 2;
  decoder_.set_max_decode_buffer_size_bytes(kMaxBufferSizeBytes);

  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                false, name, false, value);
  const size_t fragment_size = hbb.size() - 1;
  const string fragment = hbb.buffer().substr(0, fragment_size);

  HandleControlFrameHeadersStart();
  EXPECT_FALSE(HandleControlFrameHeadersData(fragment));
}

// Decode with incomplete data in buffer.
TEST_P(HpackDecoder2Test, DecodeWithIncompleteData) {
  HandleControlFrameHeadersStart();

  // No need to wait for more data.
  EXPECT_TRUE(HandleControlFrameHeadersData("\x82\x85\x82"));
  std::vector<std::pair<string, string>> expected_headers = {
      {":method", "GET"}, {":path", "/index.html"}, {":method", "GET"}};

  SpdyHeaderBlock expected_block1 = MakeHeaderBlock(expected_headers);
  EXPECT_EQ(expected_block1, decoded_block());

  // Full and partial headers, won't add partial to the headers.
  EXPECT_TRUE(
      HandleControlFrameHeadersData("\x40\x03goo"
                                    "\x03gar\xbe\x40\x04spam"));
  expected_headers.push_back({"goo", "gar"});
  expected_headers.push_back({"goo", "gar"});

  SpdyHeaderBlock expected_block2 = MakeHeaderBlock(expected_headers);
  EXPECT_EQ(expected_block2, decoded_block());

  // Add the needed data.
  EXPECT_TRUE(HandleControlFrameHeadersData("\x04gggs"));

  size_t size = 0;
  EXPECT_TRUE(HandleControlFrameHeadersComplete(&size));
  EXPECT_EQ(24u, size);

  expected_headers.push_back({"spam", "gggs"});

  SpdyHeaderBlock expected_block3 = MakeHeaderBlock(expected_headers);
  EXPECT_EQ(expected_block3, decoded_block());
}

TEST_P(HpackDecoder2Test, HandleHeaderRepresentation) {
  // Make sure the decoder is properly initialized.
  HandleControlFrameHeadersStart();
  HandleControlFrameHeadersData("");

  // All cookie crumbs are joined.
  decoder_peer_.HandleHeaderRepresentation("cookie", " part 1");
  decoder_peer_.HandleHeaderRepresentation("cookie", "part 2 ");
  decoder_peer_.HandleHeaderRepresentation("cookie", "part3");

  // Already-delimited headers are passed through.
  decoder_peer_.HandleHeaderRepresentation("passed-through",
                                           string("foo\0baz", 7));

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

  // Resulting decoded headers are in the same order as the inputs.
  EXPECT_THAT(decoded_block(),
              ElementsAre(Pair("cookie", " part 1; part 2 ; part3;  fin!"),
                          Pair("passed-through", StringPiece("foo\0baz", 7)),
                          Pair("joined", "not joined"),
                          Pair("joineD", StringPiece("value 1\0value 2", 15)),
                          Pair("empty", ""),
                          Pair("empty-joined", StringPiece("\0foo\0\0", 6))));
}

// Decoding indexed static table field should work.
TEST_P(HpackDecoder2Test, IndexedHeaderStatic) {
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

TEST_P(HpackDecoder2Test, IndexedHeaderDynamic) {
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
TEST_P(HpackDecoder2Test, InvalidIndexedHeader) {
  // High-bit set, and a prefix of one more than the number of static entries.
  EXPECT_FALSE(DecodeHeaderBlock("\xbe"));
}

TEST_P(HpackDecoder2Test, ContextUpdateMaximumSize) {
  EXPECT_EQ(kDefaultHeaderTableSizeSetting,
            decoder_peer_.header_table()->max_size());
  string input;
  {
    // Maximum-size update with size 126. Succeeds.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(126);

    output_stream.TakeString(&input);
    EXPECT_TRUE(DecodeHeaderBlock(StringPiece(input)));
    EXPECT_EQ(126u, decoder_peer_.header_table()->max_size());
  }
  {
    // Maximum-size update with kDefaultHeaderTableSizeSetting. Succeeds.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(kDefaultHeaderTableSizeSetting);

    output_stream.TakeString(&input);
    EXPECT_TRUE(DecodeHeaderBlock(StringPiece(input)));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table()->max_size());
  }
  {
    // Maximum-size update with kDefaultHeaderTableSizeSetting + 1. Fails.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(kDefaultHeaderTableSizeSetting + 1);

    output_stream.TakeString(&input);
    EXPECT_FALSE(DecodeHeaderBlock(StringPiece(input)));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table()->max_size());
  }
}

// Two HeaderTableSizeUpdates may appear at the beginning of the block
TEST_P(HpackDecoder2Test, TwoTableSizeUpdates) {
  string input;
  {
    // Should accept two table size updates, update to second one
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(0);
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(122);

    output_stream.TakeString(&input);
    EXPECT_TRUE(DecodeHeaderBlock(StringPiece(input)));
    EXPECT_EQ(122u, decoder_peer_.header_table()->max_size());
  }
}

// Three HeaderTableSizeUpdates should result in an error
TEST_P(HpackDecoder2Test, ThreeTableSizeUpdatesError) {
  string input;
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

    EXPECT_FALSE(DecodeHeaderBlock(StringPiece(input)));
    EXPECT_EQ(10u, decoder_peer_.header_table()->max_size());
  }
}

// HeaderTableSizeUpdates may only appear at the beginning of the block
// Any other updates should result in an error
TEST_P(HpackDecoder2Test, TableSizeUpdateSecondError) {
  string input;
  {
    // Should reject a table size update appearing after a different entry
    // The table size should remain as the default
    HpackOutputStream output_stream;
    output_stream.AppendBytes("\x82\x85");
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(123);

    output_stream.TakeString(&input);

    EXPECT_FALSE(DecodeHeaderBlock(StringPiece(input)));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table()->max_size());
  }
}

// HeaderTableSizeUpdates may only appear at the beginning of the block
// Any other updates should result in an error
TEST_P(HpackDecoder2Test, TableSizeUpdateFirstThirdError) {
  string input;
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

    EXPECT_FALSE(DecodeHeaderBlock(StringPiece(input)));
    EXPECT_EQ(60u, decoder_peer_.header_table()->max_size());
  }
}

// Decoding two valid encoded literal headers with no indexing should
// work.
TEST_P(HpackDecoder2Test, LiteralHeaderNoIndexing) {
  // First header with indexed name, second header with string literal
  // name.
  const char input[] = "\x04\x0c/sample/path\x00\x06:path2\x0e/sample/path/2";
  const SpdyHeaderBlock& header_set =
      DecodeBlockExpectingSuccess(StringPiece(input, arraysize(input) - 1));

  SpdyHeaderBlock expected_header_set;
  expected_header_set[":path"] = "/sample/path";
  expected_header_set[":path2"] = "/sample/path/2";
  EXPECT_EQ(expected_header_set, header_set);
}

// Decoding two valid encoded literal headers with incremental
// indexing and string literal names should work.
TEST_P(HpackDecoder2Test, LiteralHeaderIncrementalIndexing) {
  const char input[] = "\x44\x0c/sample/path\x40\x06:path2\x0e/sample/path/2";
  const SpdyHeaderBlock& header_set =
      DecodeBlockExpectingSuccess(StringPiece(input, arraysize(input) - 1));

  SpdyHeaderBlock expected_header_set;
  expected_header_set[":path"] = "/sample/path";
  expected_header_set[":path2"] = "/sample/path/2";
  EXPECT_EQ(expected_header_set, header_set);
}

TEST_P(HpackDecoder2Test, LiteralHeaderWithIndexingInvalidNameIndex) {
  decoder_.ApplyHeaderTableSizeSetting(0);

  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(StringPiece("\x7d\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(StringPiece("\x7e\x03ooo")));
}

TEST_P(HpackDecoder2Test, LiteralHeaderNoIndexingInvalidNameIndex) {
  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(StringPiece("\x0f\x2e\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(StringPiece("\x0f\x2f\x03ooo")));
}

TEST_P(HpackDecoder2Test, LiteralHeaderNeverIndexedInvalidNameIndex) {
  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(StringPiece("\x1f\x2e\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(StringPiece("\x1f\x2f\x03ooo")));
}

TEST_P(HpackDecoder2Test, TruncatedIndex) {
  // Indexed Header, varint for index requires multiple bytes,
  // but only one provided.
  EXPECT_FALSE(DecodeHeaderBlock(StringPiece("\xff", 1)));
}

TEST_P(HpackDecoder2Test, TruncatedHuffmanLiteral) {
  // Literal value, Huffman encoded, but with the last byte missing (i.e.
  // drop the final ff shown below).
  //
  // 41                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 1)
  //                                         |     :authority
  // 8c                                      |   Literal value (len = 12)
  //                                         |     Huffman encoded:
  // f1e3 c2e5 f23a 6ba0 ab90 f4ff           | .....:k.....
  //                                         |     Decoded:
  //                                         | www.example.com
  //                                         | -> :authority: www.example.com

  string first = a2b_hex("418cf1e3c2e5f23a6ba0ab90f4ff");
  EXPECT_TRUE(DecodeHeaderBlock(first));
  first = a2b_hex("418cf1e3c2e5f23a6ba0ab90f4");
  EXPECT_FALSE(DecodeHeaderBlock(first));
}

TEST_P(HpackDecoder2Test, HuffmanEOSError) {
  // Literal value, Huffman encoded, but with an additional ff byte at the end
  // of the string, i.e. an EOS that is longer than permitted.
  //
  // 41                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 1)
  //                                         |     :authority
  // 8d                                      |   Literal value (len = 13)
  //                                         |     Huffman encoded:
  // f1e3 c2e5 f23a 6ba0 ab90 f4ff           | .....:k.....
  //                                         |     Decoded:
  //                                         | www.example.com
  //                                         | -> :authority: www.example.com

  string first = a2b_hex("418cf1e3c2e5f23a6ba0ab90f4ff");
  EXPECT_TRUE(DecodeHeaderBlock(first));
  first = a2b_hex("418df1e3c2e5f23a6ba0ab90f4ffff");
  EXPECT_FALSE(DecodeHeaderBlock(first));
}

// Round-tripping the header set from RFC 7541 C.3.1 should work.
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.3.1
TEST_P(HpackDecoder2Test, BasicC31) {
  HpackEncoder encoder(ObtainHpackHuffmanTable());

  SpdyHeaderBlock expected_header_set;
  expected_header_set[":method"] = "GET";
  expected_header_set[":scheme"] = "http";
  expected_header_set[":path"] = "/";
  expected_header_set[":authority"] = "www.example.com";

  string encoded_header_set;
  EXPECT_TRUE(
      encoder.EncodeHeaderSet(expected_header_set, &encoded_header_set));

  EXPECT_TRUE(DecodeHeaderBlock(encoded_header_set));
  EXPECT_EQ(expected_header_set, decoded_block());
}

// RFC 7541, Section C.4: Request Examples with Huffman Coding
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.4
TEST_P(HpackDecoder2Test, SectionC4RequestHuffmanExamples) {
  // TODO(jamessynge): Use net/http2/hpack/tools/hpack_example.h to parse the
  // example directly, instead of having it as a comment.
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
  // 8c                                      |   Literal value (len = 12)
  //                                         |     Huffman encoded:
  // f1e3 c2e5 f23a 6ba0 ab90 f4ff           | .....:k.....
  //                                         |     Decoded:
  //                                         | www.example.com
  //                                         | -> :authority: www.example.com
  string first = a2b_hex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
  const SpdyHeaderBlock& first_header_set = DecodeBlockExpectingSuccess(first);

  EXPECT_THAT(first_header_set,
              ElementsAre(
                  // clang-format off
      Pair(":method", "GET"),
      Pair(":scheme", "http"),
      Pair(":path", "/"),
      Pair(":authority", "www.example.com")));
  // clang-format on

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

  string second = a2b_hex("828684be5886a8eb10649cbf");
  const SpdyHeaderBlock& second_header_set =
      DecodeBlockExpectingSuccess(second);

  EXPECT_THAT(second_header_set,
              ElementsAre(
                  // clang-format off
      Pair(":method", "GET"),
      Pair(":scheme", "http"),
      Pair(":path", "/"),
      Pair(":authority", "www.example.com"),
      Pair("cache-control", "no-cache")));
  // clang-format on

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
  string third = a2b_hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf");
  const SpdyHeaderBlock& third_header_set = DecodeBlockExpectingSuccess(third);

  EXPECT_THAT(
      third_header_set,
      ElementsAre(
          // clang-format off
      Pair(":method", "GET"),
      Pair(":scheme", "https"),
      Pair(":path", "/index.html"),
      Pair(":authority", "www.example.com"),
      Pair("custom-key", "custom-value")));
  // clang-format on

  expectEntry(62, 54, "custom-key", "custom-value");
  expectEntry(63, 53, "cache-control", "no-cache");
  expectEntry(64, 57, ":authority", "www.example.com");
  EXPECT_EQ(164u, decoder_peer_.header_table()->size());
}

// RFC 7541, Section C.6: Response Examples with Huffman Coding
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.6
TEST_P(HpackDecoder2Test, SectionC6ResponseHuffmanExamples) {
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

  string first = a2b_hex(
      "488264025885aec3771a4b6196d07abe"
      "941054d444a8200595040b8166e082a6"
      "2d1bff6e919d29ad171863c78f0b97c8"
      "e9ae82ae43d3");
  const SpdyHeaderBlock& first_header_set = DecodeBlockExpectingSuccess(first);

  EXPECT_THAT(first_header_set,
              ElementsAre(
                  // clang-format off
      Pair(":status", "302"),
      Pair("cache-control", "private"),
      Pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
      Pair("location", "https://www.example.com")));
  // clang-format on

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
  string second = a2b_hex("4883640effc1c0bf");
  const SpdyHeaderBlock& second_header_set =
      DecodeBlockExpectingSuccess(second);

  EXPECT_THAT(second_header_set,
              ElementsAre(
                  // clang-format off
      Pair(":status", "307"),
      Pair("cache-control", "private"),
      Pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
      Pair("location", "https://www.example.com")));
  // clang-format on

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
  string third = a2b_hex(
      "88c16196d07abe941054d444a8200595"
      "040b8166e084a62d1bffc05a839bd9ab"
      "77ad94e7821dd7f2e6c7b335dfdfcd5b"
      "3960d5af27087f3672c1ab270fb5291f"
      "9587316065c003ed4ee5b1063d5007");
  const SpdyHeaderBlock& third_header_set = DecodeBlockExpectingSuccess(third);

  EXPECT_THAT(third_header_set,
              ElementsAre(
                  // clang-format off
      Pair(":status", "200"),
      Pair("cache-control", "private"),
      Pair("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
      Pair("location", "https://www.example.com"),
      Pair("content-encoding", "gzip"),
      Pair("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU;"
           " max-age=3600; version=1")));
  // clang-format on

  expectEntry(62, 98, "set-cookie",
              "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU;"
              " max-age=3600; version=1");
  expectEntry(63, 52, "content-encoding", "gzip");
  expectEntry(64, 65, "date", "Mon, 21 Oct 2013 20:13:22 GMT");
  EXPECT_EQ(215u, decoder_peer_.header_table()->size());
}

// Regression test: Found that entries with dynamic indexed names and literal
// values caused "use after free" MSAN failures if the name was evicted as it
// was being re-used.
TEST_P(HpackDecoder2Test, ReuseNameOfEvictedEntry) {
  // Each entry is measured as 32 bytes plus the sum of the lengths of the name
  // and the value. Set the size big enough for at most one entry, and a fairly
  // small one at that (31 ASCII characters).
  decoder_.ApplyHeaderTableSizeSetting(63);

  HpackBlockBuilder hbb;

  const StringPiece name("some-name");
  const StringPiece value1("some-value");
  const StringPiece value2("another-value");
  const StringPiece value3("yet-another-value");

  // Add an entry that will become the first in the dynamic table, entry 62.
  hbb.AppendLiteralNameAndValue(HpackEntryType::kIndexedLiteralHeader, false,
                                name, false, value1);

  // Confirm that entry has been added by re-using it.
  hbb.AppendIndexedHeader(62);

  // Add another entry referring to the name of the first. This will evict the
  // first.
  hbb.AppendNameIndexAndLiteralValue(HpackEntryType::kIndexedLiteralHeader, 62,
                                     false, value2);

  // Confirm that entry has been added by re-using it.
  hbb.AppendIndexedHeader(62);

  // Add another entry referring to the name of the second. This will evict the
  // second.
  hbb.AppendNameIndexAndLiteralValue(HpackEntryType::kIndexedLiteralHeader, 62,
                                     false, value3);

  // Confirm that entry has been added by re-using it.
  hbb.AppendIndexedHeader(62);

  EXPECT_TRUE(DecodeHeaderBlock(hbb.buffer()));

  SpdyHeaderBlock expected_header_set;
  expected_header_set.AppendValueOrAddHeader(name, value1);
  expected_header_set.AppendValueOrAddHeader(name, value1);
  expected_header_set.AppendValueOrAddHeader(name, value2);
  expected_header_set.AppendValueOrAddHeader(name, value2);
  expected_header_set.AppendValueOrAddHeader(name, value3);
  expected_header_set.AppendValueOrAddHeader(name, value3);

  // SpdyHeaderBlock stores these 6 strings as '\0' separated values.
  // Make sure that is what happened.
  string joined_values = expected_header_set[name].as_string();
  EXPECT_EQ(joined_values.size(),
            2 * value1.size() + 2 * value2.size() + 2 * value3.size() + 5);

  EXPECT_EQ(expected_header_set, decoded_block());
}

}  // namespace
}  // namespace test
}  // namespace net
