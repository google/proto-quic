// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack/hpack_encoder.h"

#include <map>
#include <string>

#include "base/rand_util.h"
#include "net/base/arena.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

using base::StringPiece;
using std::string;
using std::vector;
using std::pair;
using testing::ElementsAre;

namespace test {

class HpackHeaderTablePeer {
 public:
  explicit HpackHeaderTablePeer(HpackHeaderTable* table) : table_(table) {}

  HpackHeaderTable::EntryTable* dynamic_entries() {
    return &table_->dynamic_entries_;
  }

 private:
  HpackHeaderTable* table_;
};

class HpackEncoderPeer {
 public:
  typedef HpackEncoder::Representation Representation;
  typedef HpackEncoder::Representations Representations;

  explicit HpackEncoderPeer(HpackEncoder* encoder) : encoder_(encoder) {}

  HpackHeaderTable* table() { return &encoder_->header_table_; }
  HpackHeaderTablePeer table_peer() { return HpackHeaderTablePeer(table()); }
  void set_allow_huffman_compression(bool allow) {
    encoder_->allow_huffman_compression_ = allow;
  }
  void EmitString(StringPiece str) { encoder_->EmitString(str); }
  void TakeString(string* out) { encoder_->output_stream_.TakeString(out); }
  static void CookieToCrumbs(StringPiece cookie,
                             std::vector<StringPiece>* out) {
    Representations tmp;
    HpackEncoder::CookieToCrumbs(std::make_pair("", cookie), &tmp);

    out->clear();
    for (size_t i = 0; i != tmp.size(); ++i) {
      out->push_back(tmp[i].second);
    }
  }
  static void DecomposeRepresentation(StringPiece value,
                                      std::vector<StringPiece>* out) {
    Representations tmp;
    HpackEncoder::DecomposeRepresentation(std::make_pair("foobar", value),
                                          &tmp);

    out->clear();
    for (size_t i = 0; i != tmp.size(); ++i) {
      out->push_back(tmp[i].second);
    }
  }

  // TODO(dahollings): Remove or clean up these methods when deprecating
  // non-incremental encoding path.
  static bool EncodeHeaderSet(HpackEncoder* encoder,
                              const SpdyHeaderBlock& header_set,
                              string* output,
                              bool use_compression,
                              bool use_incremental) {
    if (use_incremental) {
      return EncodeIncremental(encoder, header_set, output, use_compression);
    } else {
      return use_compression ? encoder->EncodeHeaderSet(header_set, output)
                             : encoder->EncodeHeaderSetWithoutCompression(
                                   header_set, output);
    }
  }

  static bool EncodeIncremental(HpackEncoder* encoder,
                                const SpdyHeaderBlock& header_set,
                                string* output,
                                bool use_compression) {
    std::unique_ptr<HpackEncoder::ProgressiveEncoder> encoderator =
        encoder->EncodeHeaderSet(header_set, use_compression);
    string output_buffer;
    encoderator->Next(base::RandInt(0, 15), &output_buffer);
    while (encoderator->HasNext()) {
      string second_buffer;
      encoderator->Next(base::RandInt(0, 15), &second_buffer);
      output_buffer.append(second_buffer);
    }
    *output = std::move(output_buffer);
    return true;
  }

 private:
  HpackEncoder* encoder_;
};

}  // namespace test

namespace {

using std::map;
using testing::ElementsAre;
using testing::Pair;

class HpackEncoderTest : public ::testing::TestWithParam<bool> {
 protected:
  typedef test::HpackEncoderPeer::Representations Representations;

  HpackEncoderTest()
      : encoder_(ObtainHpackHuffmanTable()),
        peer_(&encoder_),
        static_(peer_.table()->GetByIndex(1)),
        headers_storage_(1024 /* block size */) {}

  void SetUp() override {
    use_incremental_ = GetParam();

    // Populate dynamic entries into the table fixture. For simplicity each
    // entry has name.size() + value.size() == 10.
    key_1_ = peer_.table()->TryAddEntry("key1", "value1");
    key_2_ = peer_.table()->TryAddEntry("key2", "value2");
    cookie_a_ = peer_.table()->TryAddEntry("cookie", "a=bb");
    cookie_c_ = peer_.table()->TryAddEntry("cookie", "c=dd");

    // No further insertions may occur without evictions.
    peer_.table()->SetMaxSize(peer_.table()->size());

    // Disable Huffman coding by default. Most tests don't care about it.
    peer_.set_allow_huffman_compression(false);
  }

  void SaveHeaders(StringPiece name, StringPiece value) {
    StringPiece n(headers_storage_.Memdup(name.data(), name.size()),
                  name.size());
    StringPiece v(headers_storage_.Memdup(value.data(), value.size()),
                  value.size());
    headers_observed_.push_back(make_pair(n, v));
  }

  void ExpectIndex(size_t index) {
    expected_.AppendPrefix(kIndexedOpcode);
    expected_.AppendUint32(index);
  }
  void ExpectIndexedLiteral(const HpackEntry* key_entry, StringPiece value) {
    expected_.AppendPrefix(kLiteralIncrementalIndexOpcode);
    expected_.AppendUint32(IndexOf(key_entry));
    expected_.AppendPrefix(kStringLiteralIdentityEncoded);
    expected_.AppendUint32(value.size());
    expected_.AppendBytes(value);
  }
  void ExpectIndexedLiteral(StringPiece name, StringPiece value) {
    expected_.AppendPrefix(kLiteralIncrementalIndexOpcode);
    expected_.AppendUint32(0);
    expected_.AppendPrefix(kStringLiteralIdentityEncoded);
    expected_.AppendUint32(name.size());
    expected_.AppendBytes(name);
    expected_.AppendPrefix(kStringLiteralIdentityEncoded);
    expected_.AppendUint32(value.size());
    expected_.AppendBytes(value);
  }
  void ExpectNonIndexedLiteral(StringPiece name, StringPiece value) {
    expected_.AppendPrefix(kLiteralNoIndexOpcode);
    expected_.AppendUint32(0);
    expected_.AppendPrefix(kStringLiteralIdentityEncoded);
    expected_.AppendUint32(name.size());
    expected_.AppendBytes(name);
    expected_.AppendPrefix(kStringLiteralIdentityEncoded);
    expected_.AppendUint32(value.size());
    expected_.AppendBytes(value);
  }
  void ExpectHeaderTableSizeUpdate(uint32_t size) {
    expected_.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    expected_.AppendUint32(size);
  }
  void CompareWithExpectedEncoding(const SpdyHeaderBlock& header_set) {
    string expected_out, actual_out;
    expected_.TakeString(&expected_out);
    EXPECT_TRUE(test::HpackEncoderPeer::EncodeHeaderSet(
        &encoder_, header_set, &actual_out, true, use_incremental_));
    EXPECT_EQ(expected_out, actual_out);
  }
  void CompareWithExpectedEncodingWithoutCompression(
      const SpdyHeaderBlock& header_set) {
    string expected_out, actual_out;
    expected_.TakeString(&expected_out);
    EXPECT_TRUE(test::HpackEncoderPeer::EncodeHeaderSet(
        &encoder_, header_set, &actual_out, false, use_incremental_));
    EXPECT_EQ(expected_out, actual_out);
  }
  size_t IndexOf(const HpackEntry* entry) {
    return peer_.table()->IndexOf(entry);
  }

  HpackEncoder encoder_;
  test::HpackEncoderPeer peer_;

  const HpackEntry* static_;
  const HpackEntry* key_1_;
  const HpackEntry* key_2_;
  const HpackEntry* cookie_a_;
  const HpackEntry* cookie_c_;

  UnsafeArena headers_storage_;
  vector<pair<StringPiece, StringPiece>> headers_observed_;

  HpackOutputStream expected_;
  bool use_incremental_;
};

INSTANTIATE_TEST_CASE_P(HpackEncoderTests, HpackEncoderTest, ::testing::Bool());

TEST_P(HpackEncoderTest, SingleDynamicIndex) {
  encoder_.SetHeaderListener([this](StringPiece name, StringPiece value) {
    this->SaveHeaders(name, value);
  });

  ExpectIndex(IndexOf(key_2_));

  SpdyHeaderBlock headers;
  headers[key_2_->name().as_string()] = key_2_->value().as_string();
  CompareWithExpectedEncoding(headers);
  EXPECT_THAT(headers_observed_,
              ElementsAre(Pair(key_2_->name(), key_2_->value())));
}

TEST_P(HpackEncoderTest, SingleStaticIndex) {
  ExpectIndex(IndexOf(static_));

  SpdyHeaderBlock headers;
  headers[static_->name().as_string()] = static_->value().as_string();
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, SingleStaticIndexTooLarge) {
  peer_.table()->SetMaxSize(1);  // Also evicts all fixtures.
  ExpectIndex(IndexOf(static_));

  SpdyHeaderBlock headers;
  headers[static_->name().as_string()] = static_->value().as_string();
  CompareWithExpectedEncoding(headers);

  EXPECT_EQ(0u, peer_.table_peer().dynamic_entries()->size());
}

TEST_P(HpackEncoderTest, SingleLiteralWithIndexName) {
  ExpectIndexedLiteral(key_2_, "value3");

  SpdyHeaderBlock headers;
  headers[key_2_->name().as_string()] = "value3";
  CompareWithExpectedEncoding(headers);

  // A new entry was inserted and added to the reference set.
  HpackEntry* new_entry = &peer_.table_peer().dynamic_entries()->front();
  EXPECT_EQ(new_entry->name(), key_2_->name());
  EXPECT_EQ(new_entry->value(), "value3");
}

TEST_P(HpackEncoderTest, SingleLiteralWithLiteralName) {
  ExpectIndexedLiteral("key3", "value3");

  SpdyHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  HpackEntry* new_entry = &peer_.table_peer().dynamic_entries()->front();
  EXPECT_EQ(new_entry->name(), "key3");
  EXPECT_EQ(new_entry->value(), "value3");
}

TEST_P(HpackEncoderTest, SingleLiteralTooLarge) {
  peer_.table()->SetMaxSize(1);  // Also evicts all fixtures.

  ExpectIndexedLiteral("key3", "value3");

  // A header overflowing the header table is still emitted.
  // The header table is empty.
  SpdyHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  EXPECT_EQ(0u, peer_.table_peer().dynamic_entries()->size());
}

TEST_P(HpackEncoderTest, EmitThanEvict) {
  // |key_1_| is toggled and placed into the reference set,
  // and then immediately evicted by "key3".
  ExpectIndex(IndexOf(key_1_));
  ExpectIndexedLiteral("key3", "value3");

  SpdyHeaderBlock headers;
  headers[key_1_->name().as_string()] = key_1_->value().as_string();
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, CookieHeaderIsCrumbled) {
  ExpectIndex(IndexOf(cookie_a_));
  ExpectIndex(IndexOf(cookie_c_));
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "e=ff");

  SpdyHeaderBlock headers;
  headers["cookie"] = "a=bb; c=dd; e=ff";
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, StringsDynamicallySelectHuffmanCoding) {
  peer_.set_allow_huffman_compression(true);

  // Compactable string. Uses Huffman coding.
  peer_.EmitString("feedbeef");
  expected_.AppendPrefix(kStringLiteralHuffmanEncoded);
  expected_.AppendUint32(6);
  expected_.AppendBytes("\x94\xA5\x92\x32\x96_");

  // Non-compactable. Uses identity coding.
  peer_.EmitString("@@@@@@");
  expected_.AppendPrefix(kStringLiteralIdentityEncoded);
  expected_.AppendUint32(6);
  expected_.AppendBytes("@@@@@@");

  string expected_out, actual_out;
  expected_.TakeString(&expected_out);
  peer_.TakeString(&actual_out);
  EXPECT_EQ(expected_out, actual_out);
}

TEST_P(HpackEncoderTest, EncodingWithoutCompression) {
  encoder_.SetHeaderListener([this](StringPiece name, StringPiece value) {
    this->SaveHeaders(name, value);
  });

  // Implementation should internally disable.
  peer_.set_allow_huffman_compression(true);

  ExpectNonIndexedLiteral(":path", "/index.html");
  ExpectNonIndexedLiteral("cookie", "foo=bar; baz=bing");
  ExpectNonIndexedLiteral("hello", "goodbye");

  SpdyHeaderBlock headers;
  headers[":path"] = "/index.html";
  headers["cookie"] = "foo=bar; baz=bing";
  headers["hello"] = "goodbye";

  CompareWithExpectedEncodingWithoutCompression(headers);

  EXPECT_THAT(headers_observed_,
              ElementsAre(Pair(":path", "/index.html"),
                          Pair("cookie", "foo=bar; baz=bing"),
                          Pair("hello", "goodbye")));
}

TEST_P(HpackEncoderTest, MultipleEncodingPasses) {
  encoder_.SetHeaderListener([this](StringPiece name, StringPiece value) {
    this->SaveHeaders(name, value);
  });

  // Pass 1.
  {
    SpdyHeaderBlock headers;
    headers["key1"] = "value1";
    headers["cookie"] = "a=bb";

    ExpectIndex(IndexOf(key_1_));
    ExpectIndex(IndexOf(cookie_a_));
    CompareWithExpectedEncoding(headers);
  }
  // Header table is:
  // 65: key1: value1
  // 64: key2: value2
  // 63: cookie: a=bb
  // 62: cookie: c=dd
  // Pass 2.
  {
    SpdyHeaderBlock headers;
    headers["key2"] = "value2";
    headers["cookie"] = "c=dd; e=ff";

    // "key2: value2"
    ExpectIndex(64);
    // "cookie: c=dd"
    ExpectIndex(62);
    // This cookie evicts |key1| from the dynamic table.
    ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "e=ff");

    CompareWithExpectedEncoding(headers);
  }
  // Header table is:
  // 65: key2: value2
  // 64: cookie: a=bb
  // 63: cookie: c=dd
  // 62: cookie: e=ff
  // Pass 3.
  {
    SpdyHeaderBlock headers;
    headers["key2"] = "value2";
    headers["cookie"] = "a=bb; b=cc; c=dd";

    // "key2: value2"
    ExpectIndex(65);
    // "cookie: a=bb"
    ExpectIndex(64);
    // This cookie evicts |key2| from the dynamic table.
    ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "b=cc");
    // "cookie: c=dd"
    ExpectIndex(64);

    CompareWithExpectedEncoding(headers);
  }

  // clang-format off
  EXPECT_THAT(headers_observed_,
              ElementsAre(Pair("key1", "value1"),
                          Pair("cookie", "a=bb"),
                          Pair("key2", "value2"),
                          Pair("cookie", "c=dd"),
                          Pair("cookie", "e=ff"),
                          Pair("key2", "value2"),
                          Pair("cookie", "a=bb"),
                          Pair("cookie", "b=cc"),
                          Pair("cookie", "c=dd")));
  // clang-format on
}

TEST_P(HpackEncoderTest, PseudoHeadersFirst) {
  SpdyHeaderBlock headers;
  // A pseudo-header that should not be indexed.
  headers[":path"] = "/spam/eggs.html";
  // A pseudo-header to be indexed.
  headers[":authority"] = "www.example.com";
  // A regular header which precedes ":" alphabetically, should still be encoded
  // after pseudo-headers.
  headers["-foo"] = "bar";
  headers["foo"] = "bar";
  headers["cookie"] = "c=dd";

  // Headers are indexed in the order in which they were added.
  // This entry pushes "cookie: a=bb" back to 63.
  ExpectNonIndexedLiteral(":path", "/spam/eggs.html");
  ExpectIndexedLiteral(peer_.table()->GetByName(":authority"),
                       "www.example.com");
  ExpectIndexedLiteral("-foo", "bar");
  ExpectIndexedLiteral("foo", "bar");
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "c=dd");
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, CookieToCrumbs) {
  test::HpackEncoderPeer peer(NULL);
  std::vector<StringPiece> out;

  // Leading and trailing whitespace is consumed. A space after ';' is consumed.
  // All other spaces remain. ';' at beginning and end of string produce empty
  // crumbs.
  // See section 8.1.3.4 "Compressing the Cookie Header Field" in the HTTP/2
  // specification at http://tools.ietf.org/html/draft-ietf-httpbis-http2-11
  peer.CookieToCrumbs(" foo=1;bar=2 ; bar=3;  bing=4; ", &out);
  EXPECT_THAT(out, ElementsAre("foo=1", "bar=2 ", "bar=3", " bing=4", ""));

  peer.CookieToCrumbs(";;foo = bar ;; ;baz =bing", &out);
  EXPECT_THAT(out, ElementsAre("", "", "foo = bar ", "", "", "baz =bing"));

  peer.CookieToCrumbs("baz=bing; foo=bar; baz=bing", &out);
  EXPECT_THAT(out, ElementsAre("baz=bing", "foo=bar", "baz=bing"));

  peer.CookieToCrumbs("baz=bing", &out);
  EXPECT_THAT(out, ElementsAre("baz=bing"));

  peer.CookieToCrumbs("", &out);
  EXPECT_THAT(out, ElementsAre(""));

  peer.CookieToCrumbs("foo;bar; baz;baz;bing;", &out);
  EXPECT_THAT(out, ElementsAre("foo", "bar", "baz", "baz", "bing", ""));

  peer.CookieToCrumbs(" \t foo=1;bar=2 ; bar=3;\t  ", &out);
  EXPECT_THAT(out, ElementsAre("foo=1", "bar=2 ", "bar=3", ""));

  peer.CookieToCrumbs(" \t foo=1;bar=2 ; bar=3 \t  ", &out);
  EXPECT_THAT(out, ElementsAre("foo=1", "bar=2 ", "bar=3"));
}

TEST_P(HpackEncoderTest, DecomposeRepresentation) {
  test::HpackEncoderPeer peer(NULL);
  std::vector<StringPiece> out;

  peer.DecomposeRepresentation("", &out);
  EXPECT_THAT(out, ElementsAre(""));

  peer.DecomposeRepresentation("foobar", &out);
  EXPECT_THAT(out, ElementsAre("foobar"));

  peer.DecomposeRepresentation(StringPiece("foo\0bar", 7), &out);
  EXPECT_THAT(out, ElementsAre("foo", "bar"));

  peer.DecomposeRepresentation(StringPiece("\0foo\0bar", 8), &out);
  EXPECT_THAT(out, ElementsAre("", "foo", "bar"));

  peer.DecomposeRepresentation(StringPiece("foo\0bar\0", 8), &out);
  EXPECT_THAT(out, ElementsAre("foo", "bar", ""));

  peer.DecomposeRepresentation(StringPiece("\0foo\0bar\0", 9), &out);
  EXPECT_THAT(out, ElementsAre("", "foo", "bar", ""));
}

// Test that encoded headers do not have \0-delimited multiple values, as this
// became disallowed in HTTP/2 draft-14.
TEST_P(HpackEncoderTest, CrumbleNullByteDelimitedValue) {
  SpdyHeaderBlock headers;
  // A header field to be crumbled: "spam: foo\0bar".
  headers["spam"] = string("foo\0bar", 7);

  ExpectIndexedLiteral("spam", "foo");
  expected_.AppendPrefix(kLiteralIncrementalIndexOpcode);
  expected_.AppendUint32(62);
  expected_.AppendPrefix(kStringLiteralIdentityEncoded);
  expected_.AppendUint32(3);
  expected_.AppendBytes("bar");
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, HeaderTableSizeUpdate) {
  encoder_.ApplyHeaderTableSizeSetting(1024);
  ExpectHeaderTableSizeUpdate(1024);
  ExpectIndexedLiteral("key3", "value3");

  SpdyHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  HpackEntry* new_entry = &peer_.table_peer().dynamic_entries()->front();
  EXPECT_EQ(new_entry->name(), "key3");
  EXPECT_EQ(new_entry->value(), "value3");
}

TEST_P(HpackEncoderTest, HeaderTableSizeUpdateWithMin) {
  const size_t starting_size = peer_.table()->settings_size_bound();
  encoder_.ApplyHeaderTableSizeSetting(starting_size - 2);
  encoder_.ApplyHeaderTableSizeSetting(starting_size - 1);
  // We must encode the low watermark, so the peer knows to evict entries
  // if necessary.
  ExpectHeaderTableSizeUpdate(starting_size - 2);
  ExpectHeaderTableSizeUpdate(starting_size - 1);
  ExpectIndexedLiteral("key3", "value3");

  SpdyHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  HpackEntry* new_entry = &peer_.table_peer().dynamic_entries()->front();
  EXPECT_EQ(new_entry->name(), "key3");
  EXPECT_EQ(new_entry->value(), "value3");
}

TEST_P(HpackEncoderTest, HeaderTableSizeUpdateWithExistingSize) {
  encoder_.ApplyHeaderTableSizeSetting(peer_.table()->settings_size_bound());
  // No encoded size update.
  ExpectIndexedLiteral("key3", "value3");

  SpdyHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  HpackEntry* new_entry = &peer_.table_peer().dynamic_entries()->front();
  EXPECT_EQ(new_entry->name(), "key3");
  EXPECT_EQ(new_entry->value(), "value3");
}

TEST_P(HpackEncoderTest, HeaderTableSizeUpdatesWithGreaterSize) {
  const size_t starting_size = peer_.table()->settings_size_bound();
  encoder_.ApplyHeaderTableSizeSetting(starting_size + 1);
  encoder_.ApplyHeaderTableSizeSetting(starting_size + 2);
  // Only a single size update to the final size.
  ExpectHeaderTableSizeUpdate(starting_size + 2);
  ExpectIndexedLiteral("key3", "value3");

  SpdyHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  HpackEntry* new_entry = &peer_.table_peer().dynamic_entries()->front();
  EXPECT_EQ(new_entry->name(), "key3");
  EXPECT_EQ(new_entry->value(), "value3");
}

}  // namespace

}  // namespace net
