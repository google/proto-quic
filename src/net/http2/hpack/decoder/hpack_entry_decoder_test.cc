// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/decoder/hpack_entry_decoder.h"

// Tests of HpackEntryDecoder.

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "net/http2/hpack/decoder/hpack_entry_collector.h"
#include "net/http2/hpack/tools/hpack_block_builder.h"
#include "net/http2/tools/failure.h"
#include "net/http2/tools/http2_random.h"
#include "net/http2/tools/random_decoder_test.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::AssertionResult;
using std::string;

namespace net {
namespace test {
namespace {

class HpackEntryDecoderTest : public RandomDecoderTest {
 public:
  AssertionResult ValidateIndexedHeader(uint32_t ndx) {
    VERIFY_AND_RETURN_SUCCESS(collector_.ValidateIndexedHeader(ndx));
  }

  AssertionResult ValidateForIndexedLiteralValue_Literal() {
    VERIFY_AND_RETURN_SUCCESS(collector_.ValidateLiteralValueHeader(
        HpackEntryType::kIndexedLiteralHeader, 0x40, false, "custom-header"));
  }

  AssertionResult ValidateForIndexedLiteralNameValue_Literal() {
    VERIFY_AND_RETURN_SUCCESS(collector_.ValidateLiteralNameValueHeader(
        HpackEntryType::kIndexedLiteralHeader, false, "custom-key", false,
        "custom-header"));
  }

  AssertionResult ValidateForDynamicTableSizeUpdate_Literal() {
    VERIFY_AND_RETURN_SUCCESS(collector_.ValidateDynamicTableSizeUpdate(31));
  }

 protected:
  HpackEntryDecoderTest() : listener_(&collector_) {}

  DecodeStatus StartDecoding(DecodeBuffer* b) override {
    collector_.Clear();
    return decoder_.Start(b, &listener_);
  }

  DecodeStatus ResumeDecoding(DecodeBuffer* b) override {
    return decoder_.Resume(b, &listener_);
  }

  AssertionResult DecodeAndValidateSeveralWays(DecodeBuffer* db,
                                               Validator validator) {
    // StartDecoding, above, requires the DecodeBuffer be non-empty so that it
    // can call Start with the prefix byte.
    bool return_non_zero_on_first = true;
    return RandomDecoderTest::DecodeAndValidateSeveralWays(
        db, return_non_zero_on_first, validator);
  }

  AssertionResult DecodeAndValidateSeveralWays(const HpackBlockBuilder& hbb,
                                               Validator validator) {
    DecodeBuffer db(hbb.buffer());
    return DecodeAndValidateSeveralWays(&db, validator);
  }

  HpackEntryDecoder decoder_;
  HpackEntryCollector collector_;
  HpackEntryDecoderVLoggingListener listener_;
};

TEST_F(HpackEntryDecoderTest, IndexedHeader_Literals) {
  {
    const char input[] = {0x82u};  // == Index 2 ==
    DecodeBuffer b(input);
    NoArgValidator do_check =
        base::Bind(&HpackEntryDecoderTest::ValidateIndexedHeader,
                   base::Unretained(this), 2);
    EXPECT_TRUE(
        DecodeAndValidateSeveralWays(&b, ValidateDoneAndEmpty(do_check)));
    EXPECT_TRUE(do_check.Run());
  }
  collector_.Clear();
  {
    const char input[] = {0xfeu};  // == Index 126 ==
    DecodeBuffer b(input);
    NoArgValidator do_check =
        base::Bind(&HpackEntryDecoderTest::ValidateIndexedHeader,
                   base::Unretained(this), 126);
    EXPECT_TRUE(
        DecodeAndValidateSeveralWays(&b, ValidateDoneAndEmpty(do_check)));
    EXPECT_TRUE(do_check.Run());
  }
  collector_.Clear();
  {
    const char input[] = {0xffu, 0x00};  // == Index 127 ==
    DecodeBuffer b(input);
    NoArgValidator do_check =
        base::Bind(&HpackEntryDecoderTest::ValidateIndexedHeader,
                   base::Unretained(this), 127);
    EXPECT_TRUE(
        DecodeAndValidateSeveralWays(&b, ValidateDoneAndEmpty(do_check)));
    EXPECT_TRUE(do_check.Run());
  }
}

TEST_F(HpackEntryDecoderTest, IndexedHeader_Various) {
  // Indices chosen to hit encoding and table boundaries.
  for (const uint32_t ndx : {1, 2, 61, 62, 63, 126, 127, 254, 255, 256}) {
    HpackBlockBuilder hbb;
    hbb.AppendIndexedHeader(ndx);

    NoArgValidator do_check =
        base::Bind(&HpackEntryDecoderTest::ValidateIndexedHeader,
                   base::Unretained(this), ndx);
    EXPECT_TRUE(
        DecodeAndValidateSeveralWays(hbb, ValidateDoneAndEmpty(do_check)));
    EXPECT_TRUE(do_check.Run());
  }
}

TEST_F(HpackEntryDecoderTest, IndexedLiteralValue_Literal) {
  const char input[] =
      "\x7f"            // == Literal indexed, name index 0x40 ==
      "\x01"            // 2nd byte of name index (0x01 + 0x3f == 0x40)
      "\x0d"            // Value length (13)
      "custom-header";  // Value
  DecodeBuffer b(input, sizeof input - 1);
  NoArgValidator do_check =
      base::Bind(&HpackEntryDecoderTest::ValidateForIndexedLiteralValue_Literal,
                 base::Unretained(this));
  EXPECT_TRUE(DecodeAndValidateSeveralWays(&b, ValidateDoneAndEmpty(do_check)));
  EXPECT_TRUE(do_check.Run());
}

TEST_F(HpackEntryDecoderTest, IndexedLiteralNameValue_Literal) {
  const char input[] =
      "\x40"            // == Literal indexed ==
      "\x0a"            // Name length (10)
      "custom-key"      // Name
      "\x0d"            // Value length (13)
      "custom-header";  // Value

  DecodeBuffer b(input, sizeof input - 1);
  NoArgValidator do_check = base::Bind(
      &HpackEntryDecoderTest::ValidateForIndexedLiteralNameValue_Literal,
      base::Unretained(this));
  EXPECT_TRUE(DecodeAndValidateSeveralWays(&b, ValidateDoneAndEmpty(do_check)));
  EXPECT_TRUE(do_check.Run());
}

TEST_F(HpackEntryDecoderTest, DynamicTableSizeUpdate_Literal) {
  // Size update, length 31.
  const char input[] = "\x3f\x00";
  DecodeBuffer b(input, 2);
  NoArgValidator do_check = base::Bind(
      &HpackEntryDecoderTest::ValidateForDynamicTableSizeUpdate_Literal,
      base::Unretained(this));
  EXPECT_TRUE(DecodeAndValidateSeveralWays(&b, ValidateDoneAndEmpty(do_check)));
  EXPECT_TRUE(do_check.Run());
}

class HpackLiteralEntryDecoderTest
    : public HpackEntryDecoderTest,
      public ::testing::WithParamInterface<HpackEntryType> {
 public:
  AssertionResult ValidateForRandNameIndexAndLiteralValue(
      uint32_t ndx,
      bool value_is_huffman_encoded,
      const string& value) {
    VERIFY_AND_RETURN_SUCCESS(collector_.ValidateLiteralValueHeader(
        entry_type_, ndx, value_is_huffman_encoded, value));
  }

  AssertionResult ValidateForRandLiteralNameAndValue(
      bool name_is_huffman_encoded,
      const string& name,
      bool value_is_huffman_encoded,
      const string& value) {
    VERIFY_AND_RETURN_SUCCESS(collector_.ValidateLiteralNameValueHeader(
        entry_type_, name_is_huffman_encoded, name, value_is_huffman_encoded,
        value));
  }

 protected:
  HpackLiteralEntryDecoderTest() : entry_type_(GetParam()) {}

  const HpackEntryType entry_type_;
};

INSTANTIATE_TEST_CASE_P(
    AllLiteralTypes,
    HpackLiteralEntryDecoderTest,
    testing::Values(HpackEntryType::kIndexedLiteralHeader,
                    HpackEntryType::kUnindexedLiteralHeader,
                    HpackEntryType::kNeverIndexedLiteralHeader));

TEST_P(HpackLiteralEntryDecoderTest, RandNameIndexAndLiteralValue) {
  for (int n = 0; n < 10; n++) {
    const uint32_t ndx = 1 + Random().Rand8();
    const bool value_is_huffman_encoded = (n % 2) == 0;
    const string value = Random().RandString(Random().Rand8());
    HpackBlockBuilder hbb;
    hbb.AppendNameIndexAndLiteralValue(entry_type_, ndx,
                                       value_is_huffman_encoded, value);
    NoArgValidator do_check = base::Bind(
        &HpackLiteralEntryDecoderTest::ValidateForRandNameIndexAndLiteralValue,
        base::Unretained(this), ndx, value_is_huffman_encoded, value);
    EXPECT_TRUE(
        DecodeAndValidateSeveralWays(hbb, ValidateDoneAndEmpty(do_check)));
    EXPECT_TRUE(do_check.Run());
  }
}

TEST_P(HpackLiteralEntryDecoderTest, RandLiteralNameAndValue) {
  for (int n = 0; n < 10; n++) {
    const bool name_is_huffman_encoded = (n & 1) == 0;
    const int name_len = 1 + Random().Rand8();
    const string name = Random().RandString(name_len);
    const bool value_is_huffman_encoded = (n & 2) == 0;
    const int value_len = Random().Skewed(10);
    const string value = Random().RandString(value_len);
    HpackBlockBuilder hbb;
    hbb.AppendLiteralNameAndValue(entry_type_, name_is_huffman_encoded, name,
                                  value_is_huffman_encoded, value);
    NoArgValidator do_check = base::Bind(
        &HpackLiteralEntryDecoderTest::ValidateForRandLiteralNameAndValue,
        base::Unretained(this), name_is_huffman_encoded, name,
        value_is_huffman_encoded, value);
    EXPECT_TRUE(
        DecodeAndValidateSeveralWays(hbb, ValidateDoneAndEmpty(do_check)));
    EXPECT_TRUE(do_check.Run());
  }
}

}  // namespace
}  // namespace test
}  // namespace net
