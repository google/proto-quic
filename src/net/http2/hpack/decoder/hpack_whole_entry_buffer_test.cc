// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/decoder/hpack_whole_entry_buffer.h"

// Tests of HpackWholeEntryBuffer: does it buffer correctly, and does it
// detect Huffman decoding errors and oversize string errors?

#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using ::testing::AllOf;
using ::testing::HasSubstr;
using ::testing::InSequence;
using ::testing::Property;
using ::testing::StrictMock;
using ::testing::_;

namespace net {
namespace test {
namespace {

constexpr size_t kMaxStringSize = 20;

// Define HasSubstr() for base::StringPiece arguments.
// This shadows ::testing::HasSubstr(), which only works on argument types
// that can be implicilty converted to a std::string.
inline ::testing::PolymorphicMatcher<StringPieceHasSubstrMatcher> HasSubstr(
    const std::string& substring) {
  return ::testing::MakePolymorphicMatcher(
      StringPieceHasSubstrMatcher(substring));
}

class MockHpackWholeEntryListener : public HpackWholeEntryListener {
 public:
  ~MockHpackWholeEntryListener() override {}

  MOCK_METHOD1(OnIndexedHeader, void(size_t index));
  MOCK_METHOD3(OnNameIndexAndLiteralValue,
               void(HpackEntryType entry_type,
                    size_t name_index,
                    HpackDecoderStringBuffer* value_buffer));
  MOCK_METHOD3(OnLiteralNameAndValue,
               void(HpackEntryType entry_type,
                    HpackDecoderStringBuffer* name_buffer,
                    HpackDecoderStringBuffer* value_buffer));
  MOCK_METHOD1(OnDynamicTableSizeUpdate, void(size_t size));
  MOCK_METHOD1(OnHpackDecodeError, void(StringPiece error_message));
};

class HpackWholeEntryBufferTest : public ::testing::Test {
 protected:
  HpackWholeEntryBufferTest() : entry_buffer_(&listener_, kMaxStringSize) {}
  ~HpackWholeEntryBufferTest() override {}

  StrictMock<MockHpackWholeEntryListener> listener_;
  HpackWholeEntryBuffer entry_buffer_;
};

// OnIndexedHeader is an immediate pass through.
TEST_F(HpackWholeEntryBufferTest, OnIndexedHeader) {
  {
    InSequence seq;
    EXPECT_CALL(listener_, OnIndexedHeader(17));
    entry_buffer_.OnIndexedHeader(17);
  }
  {
    InSequence seq;
    EXPECT_CALL(listener_, OnIndexedHeader(62));
    entry_buffer_.OnIndexedHeader(62);
  }
  {
    InSequence seq;
    EXPECT_CALL(listener_, OnIndexedHeader(62));
    entry_buffer_.OnIndexedHeader(62);
  }
  {
    InSequence seq;
    EXPECT_CALL(listener_, OnIndexedHeader(128));
    entry_buffer_.OnIndexedHeader(128);
  }
  StrictMock<MockHpackWholeEntryListener> listener2;
  entry_buffer_.set_listener(&listener2);
  {
    InSequence seq;
    EXPECT_CALL(listener2, OnIndexedHeader(100));
    entry_buffer_.OnIndexedHeader(100);
  }
}

// OnDynamicTableSizeUpdate is an immediate pass through.
TEST_F(HpackWholeEntryBufferTest, OnDynamicTableSizeUpdate) {
  {
    InSequence seq;
    EXPECT_CALL(listener_, OnDynamicTableSizeUpdate(4096));
    entry_buffer_.OnDynamicTableSizeUpdate(4096);
  }
  {
    InSequence seq;
    EXPECT_CALL(listener_, OnDynamicTableSizeUpdate(0));
    entry_buffer_.OnDynamicTableSizeUpdate(0);
  }
  {
    InSequence seq;
    EXPECT_CALL(listener_, OnDynamicTableSizeUpdate(1024));
    entry_buffer_.OnDynamicTableSizeUpdate(1024);
  }
  {
    InSequence seq;
    EXPECT_CALL(listener_, OnDynamicTableSizeUpdate(1024));
    entry_buffer_.OnDynamicTableSizeUpdate(1024);
  }
  StrictMock<MockHpackWholeEntryListener> listener2;
  entry_buffer_.set_listener(&listener2);
  {
    InSequence seq;
    EXPECT_CALL(listener2, OnDynamicTableSizeUpdate(0));
    entry_buffer_.OnDynamicTableSizeUpdate(0);
  }
}

TEST_F(HpackWholeEntryBufferTest, OnNameIndexAndLiteralValue) {
  entry_buffer_.OnStartLiteralHeader(HpackEntryType::kNeverIndexedLiteralHeader,
                                     123);
  entry_buffer_.OnValueStart(false, 10);
  entry_buffer_.OnValueData("some data.", 10);

  // Force the value to be buffered.
  entry_buffer_.BufferStringsIfUnbuffered();

  EXPECT_CALL(
      listener_,
      OnNameIndexAndLiteralValue(
          HpackEntryType::kNeverIndexedLiteralHeader, 123,
          AllOf(Property(&HpackDecoderStringBuffer::str, "some data."),
                Property(&HpackDecoderStringBuffer::BufferedLength, 10))));

  entry_buffer_.OnValueEnd();
}

TEST_F(HpackWholeEntryBufferTest, OnLiteralNameAndValue) {
  entry_buffer_.OnStartLiteralHeader(HpackEntryType::kIndexedLiteralHeader, 0);
  // Force the name to be buffered by delivering it in two pieces.
  entry_buffer_.OnNameStart(false, 9);
  entry_buffer_.OnNameData("some-", 5);
  entry_buffer_.OnNameData("name", 4);
  entry_buffer_.OnNameEnd();
  entry_buffer_.OnValueStart(false, 12);
  entry_buffer_.OnValueData("Header Value", 12);

  EXPECT_CALL(
      listener_,
      OnLiteralNameAndValue(
          HpackEntryType::kIndexedLiteralHeader,
          AllOf(Property(&HpackDecoderStringBuffer::str, "some-name"),
                Property(&HpackDecoderStringBuffer::BufferedLength, 9)),
          AllOf(Property(&HpackDecoderStringBuffer::str, "Header Value"),
                Property(&HpackDecoderStringBuffer::BufferedLength, 0))));

  entry_buffer_.OnValueEnd();
}

// Verify that a name longer than the allowed size generates an error.
TEST_F(HpackWholeEntryBufferTest, NameTooLong) {
  entry_buffer_.OnStartLiteralHeader(HpackEntryType::kIndexedLiteralHeader, 0);
  EXPECT_CALL(listener_, OnHpackDecodeError(HasSubstr("HPACK entry name")));
  entry_buffer_.OnNameStart(false, kMaxStringSize + 1);
}

// Verify that a name longer than the allowed size generates an error.
TEST_F(HpackWholeEntryBufferTest, ValueTooLong) {
  entry_buffer_.OnStartLiteralHeader(HpackEntryType::kIndexedLiteralHeader, 1);
  EXPECT_CALL(listener_, OnHpackDecodeError(HasSubstr("HPACK entry value")));
  entry_buffer_.OnValueStart(false, kMaxStringSize + 1);
}

// Verify that a Huffman encoded name with an explicit EOS generates an error
// for an explicit EOS.
TEST_F(HpackWholeEntryBufferTest, NameHuffmanError) {
  const char data[] = "\xff\xff\xff";
  entry_buffer_.OnStartLiteralHeader(HpackEntryType::kUnindexedLiteralHeader,
                                     0);
  entry_buffer_.OnNameStart(true, 4);
  entry_buffer_.OnNameData(data, 3);

  EXPECT_CALL(listener_, OnHpackDecodeError(HasSubstr("HPACK entry name")));

  entry_buffer_.OnNameData(data, 1);

  // After an error is reported, the listener is not called again.
  EXPECT_CALL(listener_, OnDynamicTableSizeUpdate(8096)).Times(0);
  entry_buffer_.OnDynamicTableSizeUpdate(8096);
}

// Verify that a Huffman encoded value that isn't properly terminated with
// a partial EOS symbol generates an error.
TEST_F(HpackWholeEntryBufferTest, ValueeHuffmanError) {
  const char data[] = "\x00\x00\x00";
  entry_buffer_.OnStartLiteralHeader(HpackEntryType::kNeverIndexedLiteralHeader,
                                     61);
  entry_buffer_.OnValueStart(true, 3);
  entry_buffer_.OnValueData(data, 3);

  EXPECT_CALL(listener_, OnHpackDecodeError(HasSubstr("HPACK entry value")));

  entry_buffer_.OnValueEnd();

  // After an error is reported, the listener is not called again.
  EXPECT_CALL(listener_, OnIndexedHeader(17)).Times(0);
  entry_buffer_.OnIndexedHeader(17);
}

}  // namespace
}  // namespace test
}  // namespace net
