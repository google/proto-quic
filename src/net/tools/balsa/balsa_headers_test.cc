// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/balsa/balsa_headers.h"

#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "net/tools/balsa/balsa_enums.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

using ::base::StringPiece;

class BalsaBufferTest : public ::testing::Test {
 public:
  void SetUp() override {
    buffer_.reset(new BalsaBuffer);
    anotherBuffer_.reset(new BalsaBuffer);
  }

 protected:
  std::unique_ptr<BalsaBuffer> buffer_;
  std::unique_ptr<BalsaBuffer> anotherBuffer_;
};

namespace {

class BalsaHeadersTest: public ::testing::Test {
 public:
  void SetUp() override { headers_.reset(new BalsaHeaders); }

 protected:
  std::unique_ptr<BalsaHeaders> headers_;
};

class StringBuffer {
 public:
  void Write(const char* p, size_t size) {
    string_ += std::string(p, size);
  }
  const std::string& string() {return string_;}

 private:
  std::string string_;
};

TEST_F(BalsaBufferTest, EmptyBuffer) {
  ASSERT_EQ(1u, buffer_->num_blocks());
}

TEST_F(BalsaBufferTest, Write) {
  size_t index1, index2;
  StringPiece sp1 = buffer_->Write(StringPiece("hello"), &index1);
  StringPiece sp2 = buffer_->Write(StringPiece(", world"), &index2);

  ASSERT_EQ(2u, buffer_->num_blocks());
  ASSERT_EQ("hello", sp1);
  ASSERT_EQ(", world", sp2);
  ASSERT_EQ(1u, index1);
  ASSERT_EQ(1u, index2);
  ASSERT_EQ("hello, world",
            StringPiece(buffer_->GetPtr(1), buffer_->bytes_used(1)));
}

TEST_F(BalsaBufferTest, WriteLongData) {
  size_t index1, index2, index3;
  std::string as(2, 'a');
  std::string bs(BalsaBuffer::kDefaultBlocksize + 1, 'b');
  std::string cs(4, 'c');

  StringPiece sp1 = buffer_->Write(as, &index1);
  StringPiece sp2 = buffer_->Write(bs, &index2);
  StringPiece sp3 = buffer_->Write(cs, &index3);

  ASSERT_EQ(3u, buffer_->num_blocks());
  ASSERT_EQ(as, sp1);
  ASSERT_EQ(bs, sp2);
  ASSERT_EQ(cs, sp3);
  ASSERT_EQ(1u, index1);
  ASSERT_EQ(2u, index2);
  ASSERT_EQ(1u, index3);
  ASSERT_EQ("aacccc", StringPiece(buffer_->GetPtr(1), buffer_->bytes_used(1)));
  ASSERT_EQ(sp2, StringPiece(buffer_->GetPtr(2), buffer_->bytes_used(2)));
}

TEST_F(BalsaBufferTest, WriteToContiguousBuffer) {
  std::string as(2, 'a');
  std::string bs(BalsaBuffer::kDefaultBlocksize + 1, 'b');
  std::string cs(4, 'c');

  buffer_->WriteToContiguousBuffer(as);
  buffer_->WriteToContiguousBuffer(bs);
  buffer_->WriteToContiguousBuffer(cs);

  ASSERT_EQ(1u, buffer_->num_blocks());
  ASSERT_EQ(as + bs + cs,
            StringPiece(buffer_->GetPtr(0), buffer_->bytes_used(0)));
}

TEST_F(BalsaBufferTest, NoMoreWriteToContiguousBuffer) {
  size_t index1, index2;
  StringPiece sp1 = buffer_->Write(StringPiece("hello"), &index1);
  buffer_->NoMoreWriteToContiguousBuffer();
  StringPiece sp2 = buffer_->Write(StringPiece(", world"), &index2);

  ASSERT_EQ(2u, buffer_->num_blocks());
  ASSERT_EQ("hello", sp1);
  ASSERT_EQ(", world", sp2);
  ASSERT_EQ(1u, index1);
  ASSERT_EQ(0u, index2);
  ASSERT_EQ(sp1, StringPiece(buffer_->GetPtr(1), buffer_->bytes_used(1)));
  ASSERT_EQ(sp2, StringPiece(buffer_->GetPtr(0), buffer_->bytes_used(0)));
}

TEST_F(BalsaBufferTest, Clear) {
  buffer_->Write("hello", NULL);
  ASSERT_EQ(2u, buffer_->num_blocks());
  buffer_->Clear();
  ASSERT_EQ(1u, buffer_->num_blocks());
}

TEST_F(BalsaBufferTest, Swap) {
  buffer_->Write("hello", NULL);

  ASSERT_EQ(2u, buffer_->num_blocks());
  ASSERT_EQ(1u, anotherBuffer_->num_blocks());

  buffer_->Swap(anotherBuffer_.get());

  ASSERT_EQ(1u, buffer_->num_blocks());
  ASSERT_EQ(2u, anotherBuffer_->num_blocks());
  ASSERT_EQ("hello",
            StringPiece(anotherBuffer_->GetPtr(1),
                        anotherBuffer_->bytes_used(1)));
}

TEST_F(BalsaBufferTest, CopyFrom) {
  buffer_->Write("hello", NULL);

  ASSERT_EQ(2u, buffer_->num_blocks());
  ASSERT_EQ(1u, anotherBuffer_->num_blocks());

  anotherBuffer_->CopyFrom(*buffer_);

  ASSERT_EQ(2u, buffer_->num_blocks());
  ASSERT_EQ(2u, anotherBuffer_->num_blocks());
  ASSERT_EQ("hello", StringPiece(buffer_->GetPtr(1), buffer_->bytes_used(1)));
  ASSERT_EQ("hello",
            StringPiece(anotherBuffer_->GetPtr(1),
                        anotherBuffer_->bytes_used(1)));
}

TEST_F(BalsaHeadersTest, AppendHeader) {
  headers_->AppendHeader("key1", "value1");
  headers_->AppendHeader("key2", "value2");
  headers_->AppendHeader("key3", "value3");
  headers_->AppendHeader("key3", "value3.1");
  headers_->AppendHeader("key3", "value3.2");

  ASSERT_EQ(5, std::distance(headers_->header_lines_begin(),
                             headers_->header_lines_end()));
  ASSERT_EQ("value1", headers_->GetHeader("key1"));
  ASSERT_EQ("value2", headers_->GetHeader("key2"));
  ASSERT_EQ("value3", headers_->GetHeader("key3"));

  std::vector<base::StringPiece> v1, v2, v3;
  std::string s1, s2, s3;
  headers_->GetAllOfHeader("key1", &v1);
  headers_->GetAllOfHeader("key2", &v2);
  headers_->GetAllOfHeader("key3", &v3);
  headers_->GetAllOfHeaderAsString("key1", &s1);
  headers_->GetAllOfHeaderAsString("key2", &s2);
  headers_->GetAllOfHeaderAsString("key3", &s3);

  ASSERT_EQ(1u, v1.size());
  ASSERT_EQ(1u, v2.size());
  ASSERT_EQ(3u, v3.size());
  ASSERT_EQ("value1", v1[0]);
  ASSERT_EQ("value2", v2[0]);
  ASSERT_EQ("value3", v3[0]);
  ASSERT_EQ("value3.1", v3[1]);
  ASSERT_EQ("value3.2", v3[2]);
  ASSERT_EQ("value1", s1);
  ASSERT_EQ("value2", s2);
  ASSERT_EQ("value3,value3.1,value3.2", s3);
}

TEST_F(BalsaHeadersTest, ReplaceOrAppendHeader) {
  headers_->ReplaceOrAppendHeader("key1", "value1");
  headers_->ReplaceOrAppendHeader("key1", "value2");

  ASSERT_EQ(1, std::distance(headers_->header_lines_begin(),
                             headers_->header_lines_end()));
  ASSERT_EQ("value2", headers_->GetHeader("key1"));

  std::vector<base::StringPiece> v;
  headers_->GetAllOfHeader("key1", &v);

  ASSERT_EQ(1u, v.size());
  ASSERT_EQ("value2", v[0]);
}

TEST_F(BalsaHeadersTest, AppendToHeader) {
  headers_->AppendToHeader("key1", "value1");
  headers_->AppendToHeader("keY1", "value2");

  ASSERT_EQ(1, std::distance(headers_->header_lines_begin(),
                             headers_->header_lines_end()));
  ASSERT_EQ("value1,value2", headers_->GetHeader("key1"));

  std::vector<base::StringPiece> v;
  std::string s;
  headers_->GetAllOfHeader("key1", &v);
  headers_->GetAllOfHeaderAsString("keY1", &s);

  ASSERT_EQ(1u, v.size());
  ASSERT_EQ("value1,value2", v[0]);
  ASSERT_EQ("value1,value2", s);
}

TEST_F(BalsaHeadersTest, PrepentToHeader) {
  headers_->PrependToHeader("key1", "value1");
  headers_->PrependToHeader("key1", "value2");

  ASSERT_EQ(1, std::distance(headers_->header_lines_begin(),
                             headers_->header_lines_end()));
  ASSERT_EQ("value2,value1", headers_->GetHeader("key1"));

  std::vector<base::StringPiece> v;
  std::string s;
  headers_->GetAllOfHeader("key1", &v);
  headers_->GetAllOfHeaderAsString("key1", &s);

  ASSERT_EQ(1u, v.size());
  ASSERT_EQ("value2,value1", v[0]);
  ASSERT_EQ("value2,value1", s);
}

TEST_F(BalsaHeadersTest, HasHeader) {
  headers_->AppendHeader("key1", "value1");

  ASSERT_TRUE(headers_->HasHeader("key1"));
  ASSERT_FALSE(headers_->HasHeader("value1"));
  ASSERT_FALSE(headers_->HasHeader("key2"));
}

TEST_F(BalsaHeadersTest, HasNonEmptyHeader) {
  headers_->AppendHeader("key1", "value1");
  headers_->AppendHeader("key2", "");

  ASSERT_TRUE(headers_->HasNonEmptyHeader("key1"));
  ASSERT_FALSE(headers_->HasNonEmptyHeader("key2"));
  ASSERT_FALSE(headers_->HasNonEmptyHeader("key3"));
}

TEST_F(BalsaHeadersTest, GetHeaderPosition) {
  headers_->AppendHeader("key1", "value1");
  headers_->AppendHeader("key2", "value2");
  headers_->AppendHeader("key3", "value3");

  BalsaHeaders::const_header_lines_iterator i =
      headers_->GetHeaderPosition("key2");

  ASSERT_EQ(headers_->header_lines_end(),
            headers_->GetHeaderPosition("foobar"));
  ASSERT_EQ(headers_->header_lines_begin(),
            headers_->GetHeaderPosition("key1"));
  ASSERT_NE(headers_->header_lines_end(), i);
  ASSERT_EQ("key2", i->first);
  ASSERT_EQ("value2", i->second);
  ++i;
  ASSERT_EQ("key3", i->first);
  ASSERT_EQ("value3", i->second);
  ++i;
  ASSERT_EQ(headers_->header_lines_end(), i);
}

TEST_F(BalsaHeadersTest, GetIteratorForKey) {
  headers_->AppendHeader("key1", "value1");
  headers_->AppendHeader("key2", "value2");
  headers_->AppendHeader("key1", "value1.1");
  headers_->AppendHeader("key3", "value3");
  headers_->AppendHeader("KEY1", "value1.2");

  BalsaHeaders::const_header_lines_key_iterator i =
      headers_->GetIteratorForKey("key1");

  ASSERT_EQ(headers_->header_lines_key_end(),
            headers_->GetIteratorForKey("foobar"));
  ASSERT_NE(headers_->header_lines_key_end(), i);
  ASSERT_EQ("key1", i->first);
  ASSERT_EQ("value1", i->second);
  ++i;
  ASSERT_EQ("key1", i->first);
  ASSERT_EQ("value1.1", i->second);
  ++i;
  ASSERT_EQ("KEY1", i->first);
  ASSERT_EQ("value1.2", i->second);
  ++i;
  ASSERT_EQ(headers_->header_lines_key_end(), i);
}

TEST_F(BalsaHeadersTest, RemoveAllOfHeader) {
  headers_->AppendHeader("key1", "value1");
  headers_->AppendHeader("key2", "value2");
  headers_->AppendHeader("key1", "value1.1");
  headers_->AppendHeader("key3", "value3");
  headers_->AppendHeader("key1", "value1.2");
  headers_->AppendHeader("kEY1", "value1.3");

  ASSERT_EQ(6, std::distance(headers_->header_lines_begin(),
                             headers_->header_lines_end()));
  headers_->RemoveAllOfHeader("key1");
  ASSERT_EQ(2, std::distance(headers_->header_lines_begin(),
                             headers_->header_lines_end()));
}

TEST_F(BalsaHeadersTest, RemoveAllHeadersWithPrefix) {
  headers_->AppendHeader("1key", "value1");
  headers_->AppendHeader("2key", "value2");
  headers_->AppendHeader("1kEz", "value1.1");
  headers_->AppendHeader("key3", "value3");
  headers_->AppendHeader("1KEEjkladf", "value1.2");

  ASSERT_EQ(5, std::distance(headers_->header_lines_begin(),
                             headers_->header_lines_end()));
  headers_->RemoveAllHeadersWithPrefix("1ke");
  ASSERT_EQ(2, std::distance(headers_->header_lines_begin(),
                             headers_->header_lines_end()));
}

TEST_F(BalsaHeadersTest, WriteRequestHeaderAndEndingToBuffer) {
  headers_->AppendHeader("key1", "value1");
  headers_->AppendHeader("key2", "value2");
  headers_->AppendHeader("key1", "value1.1");

  headers_->SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");

  std::string expected = "GET / HTTP/1.0\r\n"
      "key1: value1\r\n"
      "key2: value2\r\n"
      "key1: value1.1\r\n\r\n";
  StringBuffer buffer;
  headers_->WriteHeaderAndEndingToBuffer(&buffer);
  ASSERT_EQ(expected, buffer.string());
}

TEST_F(BalsaHeadersTest, WriteResponseHeaderAndEndingToBuffer) {
  headers_->AppendHeader("key1", "value1");
  headers_->AppendHeader("key2", "value2");
  headers_->AppendHeader("key1", "value1.1");

  headers_->SetResponseFirstlineFromStringPieces("HTTP/1.0", "200", "OK");

  std::string expected = "HTTP/1.0 200 OK\r\n"
      "key1: value1\r\n"
      "key2: value2\r\n"
      "key1: value1.1\r\n\r\n";
  StringBuffer buffer;
  headers_->WriteHeaderAndEndingToBuffer(&buffer);
  ASSERT_EQ(expected, buffer.string());
}

TEST_F(BalsaHeadersTest, RequestFirstLine) {
  headers_->SetRequestFirstlineFromStringPieces("HEAD", "/path", "HTTP/1.1");

  ASSERT_EQ("HEAD /path HTTP/1.1", headers_->first_line());
  ASSERT_EQ("HEAD", headers_->request_method());
  ASSERT_EQ("/path", headers_->request_uri());
  ASSERT_EQ("HTTP/1.1", headers_->request_version());
}

TEST_F(BalsaHeadersTest, ResponseFirstLine) {
  headers_->SetRequestFirstlineFromStringPieces("HTTP/1.0", "403", "FORBIDDEN");

  ASSERT_EQ("HTTP/1.0 403 FORBIDDEN", headers_->first_line());
  ASSERT_EQ("HTTP/1.0", headers_->response_version());
  ASSERT_EQ("403", headers_->response_code());
  ASSERT_EQ("FORBIDDEN", headers_->response_reason_phrase());
}

}  // namespace

}  // namespace net
