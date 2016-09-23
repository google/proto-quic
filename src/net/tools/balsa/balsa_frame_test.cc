// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/balsa/balsa_frame.h"

#include <iterator>
#include <memory>

#include "base/strings/string_piece.h"
#include "net/tools/balsa/balsa_enums.h"
#include "net/tools/balsa/balsa_headers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

using ::base::StringPiece;
using ::testing::_;
using ::testing::InSequence;
using ::testing::SaveArg;

class Visitor : public BalsaVisitorInterface {
 public:
  virtual ~Visitor() {}
  MOCK_METHOD2(ProcessBodyInput, void(const char*, size_t));
  MOCK_METHOD2(ProcessBodyData, void(const char*, size_t));
  MOCK_METHOD2(ProcessHeaderInput, void(const char*, size_t));
  MOCK_METHOD2(ProcessTrailerInput, void(const char*, size_t));
  MOCK_METHOD1(ProcessHeaders, void(const BalsaHeaders&));
  MOCK_METHOD8(ProcessRequestFirstLine, void(const char*,
                                             size_t,
                                             const char*,
                                             size_t,
                                             const char*,
                                             size_t,
                                             const char*,
                                             size_t));
  MOCK_METHOD8(ProcessResponseFirstLine, void(const char*,
                                              size_t,
                                              const char*,
                                              size_t,
                                              const char*,
                                              size_t,
                                              const char*,
                                              size_t));
  MOCK_METHOD2(ProcessChunkExtensions, void(const char*, size_t));
  MOCK_METHOD1(ProcessChunkLength, void(size_t));
  MOCK_METHOD0(HeaderDone, void());
  MOCK_METHOD0(MessageDone, void());
  MOCK_METHOD1(HandleHeaderError, void(BalsaFrame*));
  MOCK_METHOD1(HandleHeaderWarning, void(BalsaFrame*));
  MOCK_METHOD1(HandleChunkingError, void(BalsaFrame*));
  MOCK_METHOD1(HandleBodyError, void(BalsaFrame*));
};

class BalsaFrameTest : public ::testing::Test {
 public:
  void SetUp() override {
    frame_.reset(new BalsaFrame);
    frame_headers_.reset(new BalsaHeaders);
    visitor_.reset(new Visitor);
    frame_->set_balsa_visitor(visitor_.get());
  };

 protected:
  std::unique_ptr<BalsaFrame> frame_;
  std::unique_ptr<BalsaHeaders> frame_headers_;
  std::unique_ptr<Visitor> visitor_;
};

TEST_F(BalsaFrameTest, EmptyFrame) {
  ASSERT_EQ(BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE,
            frame_->ParseState());
  ASSERT_FALSE(frame_->MessageFullyRead());
  ASSERT_FALSE(frame_->Error());
  ASSERT_EQ(NULL, frame_->const_balsa_headers());
  ASSERT_EQ(NULL, frame_->balsa_headers());
  ASSERT_EQ(NULL, frame_->headers());
  ASSERT_EQ(NULL, frame_->mutable_headers());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());
  ASSERT_TRUE(frame_->is_request());
  ASSERT_FALSE(frame_->request_was_head());
}

TEST_F(BalsaFrameTest, EmptyRequest) {
  const char input[] = "\r\n";
  frame_->set_balsa_headers(frame_headers_.get());

  {
    InSequence s;
    // No visitor callback should be called.
  }
  size_t read = frame_->ProcessInput(input, strlen(input));
  EXPECT_EQ(2u, read);
  ASSERT_EQ(BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE,
            frame_->ParseState());
  ASSERT_FALSE(frame_->Error());
  ASSERT_EQ(BalsaFrameEnums::NO_ERROR, frame_->ErrorCode());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());
}

TEST_F(BalsaFrameTest, GetRequest) {
  const char input[] = "GET / HTTP/1.0\r\nkey1: value1\r\n\r\n";
  const char* line = NULL;
  size_t line_length = 0;
  const char* method = NULL;
  size_t method_length = 0;
  const char* request_uri = NULL;
  size_t request_uri_length = 0;
  const char* version = NULL;
  size_t version_length = 0;
  const char* header = NULL;
  size_t header_length = 0;

  {
    InSequence s;
    EXPECT_CALL(*visitor_, ProcessRequestFirstLine(_, _, _, _, _, _, _, _))
        .WillOnce(DoAll(SaveArg<0>(&line),
                        SaveArg<1>(&line_length),
                        SaveArg<2>(&method),
                        SaveArg<3>(&method_length),
                        SaveArg<4>(&request_uri),
                        SaveArg<5>(&request_uri_length),
                        SaveArg<6>(&version),
                        SaveArg<7>(&version_length)));
    EXPECT_CALL(*visitor_, ProcessHeaderInput(_, _))
        .WillOnce(DoAll(SaveArg<0>(&header), SaveArg<1>(&header_length)));
    EXPECT_CALL(*visitor_, ProcessHeaders(_));
    EXPECT_CALL(*visitor_, HeaderDone());
    EXPECT_CALL(*visitor_, MessageDone());
  }

  frame_->set_balsa_headers(frame_headers_.get());
  ASSERT_EQ(frame_headers_.get(), frame_->const_balsa_headers());
  ASSERT_EQ(frame_headers_.get(), frame_->balsa_headers());
  ASSERT_EQ(frame_headers_.get(), frame_->headers());
  ASSERT_EQ(frame_headers_.get(), frame_->mutable_headers());

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(strlen(input), read);
  ASSERT_EQ(BalsaFrameEnums::MESSAGE_FULLY_READ, frame_->ParseState());
  ASSERT_TRUE(frame_->MessageFullyRead());
  ASSERT_FALSE(frame_->Error());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());
  ASSERT_EQ("GET / HTTP/1.0", StringPiece(line, line_length));
  ASSERT_EQ("GET", StringPiece(method, method_length));
  ASSERT_EQ("/", StringPiece(request_uri, request_uri_length));
  ASSERT_EQ("HTTP/1.0", StringPiece(version, version_length));
  ASSERT_EQ(input, StringPiece(header, header_length));
}

TEST_F(BalsaFrameTest, HeadResponse) {
  const char input[] = "HTTP/1.1 200 OK\r\n"
      "Content-type: text/plain\r\n"
      "Content-Length: 14\r\n\r\n";
  const char* line = NULL;
  size_t line_length = 0;
  const char* version = NULL;
  size_t version_length = 0;
  const char* status = NULL;
  size_t status_length = 0;
  const char* reason = NULL;
  size_t reason_length = 0;
  const char* header = NULL;
  size_t header_length = 0;

  frame_->set_balsa_headers(frame_headers_.get());
  frame_->set_is_request(false);
  frame_->set_request_was_head(true);

  {
    InSequence s;
    EXPECT_CALL(*visitor_, ProcessResponseFirstLine(_, _, _, _, _, _, _, _))
        .WillOnce(DoAll(SaveArg<0>(&line),
                        SaveArg<1>(&line_length),
                        SaveArg<2>(&version),
                        SaveArg<3>(&version_length),
                        SaveArg<4>(&status),
                        SaveArg<5>(&status_length),
                        SaveArg<6>(&reason),
                        SaveArg<7>(&reason_length)));
    EXPECT_CALL(*visitor_, ProcessHeaderInput(_, _))
        .WillOnce(DoAll(SaveArg<0>(&header), SaveArg<1>(&header_length)));
    EXPECT_CALL(*visitor_, ProcessHeaders(_));
    EXPECT_CALL(*visitor_, HeaderDone());
    EXPECT_CALL(*visitor_, MessageDone());
  }

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(strlen(input), read);
  ASSERT_EQ(BalsaFrameEnums::MESSAGE_FULLY_READ, frame_->ParseState());
  ASSERT_TRUE(frame_->MessageFullyRead());
  ASSERT_FALSE(frame_->Error());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());

  ASSERT_EQ("HTTP/1.1 200 OK", StringPiece(line, line_length));
  ASSERT_EQ("HTTP/1.1", StringPiece(version, version_length));
  ASSERT_EQ("200", StringPiece(status, status_length));
  ASSERT_EQ("OK", StringPiece(reason, reason_length));
  ASSERT_EQ("HTTP/1.1 200 OK\r\n"
            "Content-type: text/plain\r\n"
            "Content-Length: 14\r\n\r\n",
            StringPiece(header, header_length));
}

TEST_F(BalsaFrameTest, GetResponse) {
  const char input[] = "HTTP/1.1 200 OK\r\n"
      "Content-type: text/plain\r\n"
      "Content-Length: 14\r\n\r\n"
      "hello, world\r\n";
  const char* line = NULL;
  size_t line_length = 0;
  const char* version = NULL;
  size_t version_length = 0;
  const char* status = NULL;
  size_t status_length = 0;
  const char* reason = NULL;
  size_t reason_length = 0;
  const char* header = NULL;
  size_t header_length = 0;
  const char* body = NULL;
  size_t body_length = 0;
  const char* body_data = NULL;
  size_t body_data_length = 0;
  testing::MockFunction<void(int)> checkpoint;

  frame_->set_balsa_headers(frame_headers_.get());
  frame_->set_is_request(false);

  {
    InSequence s;
    EXPECT_CALL(*visitor_, ProcessResponseFirstLine(_, _, _, _, _, _, _, _))
        .WillOnce(DoAll(SaveArg<0>(&line),
                        SaveArg<1>(&line_length),
                        SaveArg<2>(&version),
                        SaveArg<3>(&version_length),
                        SaveArg<4>(&status),
                        SaveArg<5>(&status_length),
                        SaveArg<6>(&reason),
                        SaveArg<7>(&reason_length)));
    EXPECT_CALL(*visitor_, ProcessHeaderInput(_, _))
        .WillOnce(DoAll(SaveArg<0>(&header), SaveArg<1>(&header_length)));
    EXPECT_CALL(*visitor_, ProcessHeaders(_));
    EXPECT_CALL(*visitor_, HeaderDone());
    EXPECT_CALL(checkpoint, Call(0));
    EXPECT_CALL(*visitor_, ProcessBodyInput(_, _))
        .WillOnce(DoAll(SaveArg<0>(&body), SaveArg<1>(&body_length)));
    EXPECT_CALL(*visitor_, ProcessBodyData(_, _))
        .WillOnce(DoAll(SaveArg<0>(&body_data), SaveArg<1>(&body_data_length)));
    EXPECT_CALL(*visitor_, MessageDone());
  }

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(65u, read);
  ASSERT_EQ(BalsaFrameEnums::READING_CONTENT, frame_->ParseState());
  checkpoint.Call(0);
  read += frame_->ProcessInput(&input[read], strlen(input) - read);
  ASSERT_EQ(strlen(input), read);
  ASSERT_EQ(BalsaFrameEnums::MESSAGE_FULLY_READ, frame_->ParseState());
  ASSERT_TRUE(frame_->MessageFullyRead());
  ASSERT_FALSE(frame_->Error());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());

  ASSERT_EQ("HTTP/1.1 200 OK", StringPiece(line, line_length));
  ASSERT_EQ("HTTP/1.1", StringPiece(version, version_length));
  ASSERT_EQ("200", StringPiece(status, status_length));
  ASSERT_EQ("OK", StringPiece(reason, reason_length));
  ASSERT_EQ("HTTP/1.1 200 OK\r\n"
            "Content-type: text/plain\r\n"
            "Content-Length: 14\r\n\r\n",
            StringPiece(header, header_length));
  ASSERT_EQ("hello, world\r\n", StringPiece(body, body_length));
  ASSERT_EQ("hello, world\r\n", StringPiece(body_data, body_data_length));
}

TEST_F(BalsaFrameTest, Reset) {
  const char input[] = "GET / HTTP/1.0\r\nkey1: value1\r\n\r\n";

  {
    InSequence s;
    EXPECT_CALL(*visitor_, ProcessRequestFirstLine(_, _, _, _, _, _, _, _));
    EXPECT_CALL(*visitor_, ProcessHeaderInput(_, _));
    EXPECT_CALL(*visitor_, ProcessHeaders(_));
    EXPECT_CALL(*visitor_, HeaderDone());
    EXPECT_CALL(*visitor_, MessageDone());
  }

  frame_->set_balsa_headers(frame_headers_.get());

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(strlen(input), read);
  ASSERT_EQ(BalsaFrameEnums::MESSAGE_FULLY_READ, frame_->ParseState());
  ASSERT_TRUE(frame_->MessageFullyRead());
  ASSERT_FALSE(frame_->Error());

  frame_->Reset();
  ASSERT_EQ(BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE,
            frame_->ParseState());
  ASSERT_FALSE(frame_->MessageFullyRead());
  ASSERT_FALSE(frame_->Error());
}

TEST_F(BalsaFrameTest, InvalidStatusCode) {
  const char input[] = "HTTP/1.1 InvalidStatusCode OK\r\n"
      "Content-type: text/plain\r\n"
      "Content-Length: 14\r\n\r\n"
      "hello, world\r\n";

  frame_->set_balsa_headers(frame_headers_.get());
  frame_->set_is_request(false);

  {
    InSequence s;
    EXPECT_CALL(*visitor_, HandleHeaderError(frame_.get()));
  }

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(30u, read);
  ASSERT_EQ(BalsaFrameEnums::PARSE_ERROR, frame_->ParseState());
  ASSERT_EQ(BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT,
            frame_->ErrorCode());
  ASSERT_FALSE(frame_->MessageFullyRead());
  ASSERT_TRUE(frame_->Error());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());
}

TEST_F(BalsaFrameTest, ResetError) {
  const char input[] = "HTTP/1.1 InvalidStatusCode OK\r\n"
      "Content-type: text/plain\r\n"
      "Content-Length: 14\r\n\r\n"
      "hello, world\r\n";

  frame_->set_balsa_headers(frame_headers_.get());
  frame_->set_is_request(false);

  {
    InSequence s;
    EXPECT_CALL(*visitor_, HandleHeaderError(frame_.get()));
  }

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(30u, read);
  ASSERT_EQ(BalsaFrameEnums::PARSE_ERROR, frame_->ParseState());
  ASSERT_EQ(BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT,
            frame_->ErrorCode());
  ASSERT_FALSE(frame_->MessageFullyRead());
  ASSERT_TRUE(frame_->Error());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());

  frame_->Reset();
  ASSERT_EQ(BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE,
            frame_->ParseState());
  ASSERT_FALSE(frame_->MessageFullyRead());
  ASSERT_FALSE(frame_->Error());
}

TEST_F(BalsaFrameTest, RequestURITooLong) {
  const char input[] = "GET / HTTP/1.0\r\n\r\n";

  frame_->set_balsa_headers(frame_headers_.get());
  frame_->set_max_request_uri_length(0);

  {
    InSequence s;
    EXPECT_CALL(*visitor_, HandleHeaderError(frame_.get()));
  }

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(15u, read);
  ASSERT_EQ(BalsaFrameEnums::PARSE_ERROR, frame_->ParseState());
  ASSERT_EQ(BalsaFrameEnums::REQUEST_URI_TOO_LONG, frame_->ErrorCode());
  ASSERT_FALSE(frame_->MessageFullyRead());
  ASSERT_TRUE(frame_->Error());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());
}

TEST_F(BalsaFrameTest, HeadersTooLong) {
  const char input[] = "GET / HTTP/1.0\r\n\r\n";

  frame_->set_balsa_headers(frame_headers_.get());
  frame_->set_max_header_length(0);

  {
    InSequence s;
    EXPECT_CALL(*visitor_, HandleHeaderError(frame_.get()));
  }

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(0u, read);
  ASSERT_EQ(BalsaFrameEnums::PARSE_ERROR, frame_->ParseState());
  ASSERT_EQ(BalsaFrameEnums::HEADERS_TOO_LONG, frame_->ErrorCode());
  ASSERT_FALSE(frame_->MessageFullyRead());
  ASSERT_TRUE(frame_->Error());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());
}

TEST_F(BalsaFrameTest, InvalidHeader) {
  const char input[] = "GET / HTTP/1.0\r\n"
      "foo bar baz\r\n"
      "Content-Type: text/plain\r\n\r\n";
  const char* line = NULL;
  size_t line_length = 0;
  const char* method = NULL;
  size_t method_length = 0;
  const char* request_uri = NULL;
  size_t request_uri_length = 0;
  const char* version = NULL;
  size_t version_length = 0;

  frame_->set_balsa_headers(frame_headers_.get());

  {
    InSequence s;
    EXPECT_CALL(*visitor_, ProcessRequestFirstLine(_, _, _, _, _, _, _, _))
        .WillOnce(DoAll(SaveArg<0>(&line),
                        SaveArg<1>(&line_length),
                        SaveArg<2>(&method),
                        SaveArg<3>(&method_length),
                        SaveArg<4>(&request_uri),
                        SaveArg<5>(&request_uri_length),
                        SaveArg<6>(&version),
                        SaveArg<7>(&version_length)));
    EXPECT_CALL(*visitor_, ProcessHeaderInput(_, _));
    EXPECT_CALL(*visitor_, HandleHeaderWarning(frame_.get()));
    EXPECT_CALL(*visitor_, ProcessHeaders(_));
    EXPECT_CALL(*visitor_, HeaderDone());
    EXPECT_CALL(*visitor_, MessageDone());
  }

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(strlen(input), read);
  ASSERT_EQ(BalsaFrameEnums::MESSAGE_FULLY_READ, frame_->ParseState());
  ASSERT_EQ(BalsaFrameEnums::HEADER_MISSING_COLON, frame_->ErrorCode());
  ASSERT_TRUE(frame_->MessageFullyRead());
  ASSERT_FALSE(frame_->Error());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());
  ASSERT_EQ("GET / HTTP/1.0", StringPiece(line, line_length));
  ASSERT_EQ("GET", StringPiece(method, method_length));
  ASSERT_EQ("/", StringPiece(request_uri, request_uri_length));
  ASSERT_EQ("HTTP/1.0", StringPiece(version, version_length));
  ASSERT_EQ(2, std::distance(frame_headers_->header_lines_begin(),
                              frame_headers_->header_lines_end()));
}

TEST_F(BalsaFrameTest, GetResponseSplit) {
  const char input[] = "HTTP/1.1 200 OK\r\n"
      "Content-type: text/plain\r\n"
      "Content-Length: 14\r\n\r\n"
      "hello";
  const char input2[] = ", world\r\n";
  const char* body1 = NULL;
  size_t body1_length = 0;
  const char* body1_data = NULL;
  size_t body1_data_length = 0;
  const char* body2 = NULL;
  size_t body2_length = 0;
  const char* body2_data = NULL;
  size_t body2_data_length = 0;
  testing::MockFunction<void(int)> checkpoint;

  frame_->set_balsa_headers(frame_headers_.get());
  frame_->set_is_request(false);

  {
    InSequence s;
    EXPECT_CALL(*visitor_, ProcessResponseFirstLine(_, _, _, _, _, _, _, _));
    EXPECT_CALL(*visitor_, ProcessHeaderInput(_, _));
    EXPECT_CALL(*visitor_, ProcessHeaders(_));
    EXPECT_CALL(*visitor_, HeaderDone());
    EXPECT_CALL(checkpoint, Call(0));
    EXPECT_CALL(*visitor_, ProcessBodyInput(_, _))
        .WillOnce(DoAll(SaveArg<0>(&body1), SaveArg<1>(&body1_length)));
    EXPECT_CALL(*visitor_, ProcessBodyData(_, _))
        .WillOnce(DoAll(SaveArg<0>(&body1_data),
                        SaveArg<1>(&body1_data_length)));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*visitor_, ProcessBodyInput(_, _))
        .WillOnce(DoAll(SaveArg<0>(&body2), SaveArg<1>(&body2_length)));
    EXPECT_CALL(*visitor_, ProcessBodyData(_, _))
        .WillOnce(DoAll(SaveArg<0>(&body2_data),
                        SaveArg<1>(&body2_data_length)));
    EXPECT_CALL(*visitor_, MessageDone());
  }

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(65u, read);
  ASSERT_EQ(BalsaFrameEnums::READING_CONTENT, frame_->ParseState());
  checkpoint.Call(0);
  read += frame_->ProcessInput(&input[read], strlen(input) - read);
  ASSERT_EQ(strlen(input), read);
  ASSERT_EQ(BalsaFrameEnums::READING_CONTENT, frame_->ParseState());
  checkpoint.Call(1);
  ASSERT_EQ(9u, frame_->BytesSafeToSplice());
  read = frame_->ProcessInput(input2, strlen(input2));
  ASSERT_EQ(strlen(input2), read);

  ASSERT_EQ(BalsaFrameEnums::MESSAGE_FULLY_READ, frame_->ParseState());
  ASSERT_TRUE(frame_->MessageFullyRead());
  ASSERT_FALSE(frame_->Error());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());
  ASSERT_EQ("hello", StringPiece(body1, body1_length));
  ASSERT_EQ("hello", StringPiece(body1_data, body1_data_length));
  ASSERT_EQ(", world\r\n", StringPiece(body2, body2_length));
  ASSERT_EQ(", world\r\n", StringPiece(body2_data, body2_data_length));
}

TEST_F(BalsaFrameTest, GetResponseBytesSpliced) {
  const char input[] = "HTTP/1.1 200 OK\r\n"
      "Content-type: text/plain\r\n"
      "Content-Length: 14\r\n\r\n"
      "hello";
  testing::MockFunction<void(int)> checkpoint;

  frame_->set_balsa_headers(frame_headers_.get());
  frame_->set_is_request(false);

  {
    InSequence s;
    EXPECT_CALL(*visitor_, ProcessResponseFirstLine(_, _, _, _, _, _, _, _));
    EXPECT_CALL(*visitor_, ProcessHeaderInput(_, _));
    EXPECT_CALL(*visitor_, ProcessHeaders(_));
    EXPECT_CALL(*visitor_, HeaderDone());
    EXPECT_CALL(checkpoint, Call(0));
    EXPECT_CALL(*visitor_, ProcessBodyInput(_, _));
    EXPECT_CALL(*visitor_, ProcessBodyData(_, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(checkpoint, Call(2));
    EXPECT_CALL(*visitor_, MessageDone());
  }

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(65u, read);
  ASSERT_EQ(BalsaFrameEnums::READING_CONTENT, frame_->ParseState());
  checkpoint.Call(0);
  read += frame_->ProcessInput(&input[read], strlen(input) - read);
  ASSERT_EQ(strlen(input), read);
  ASSERT_EQ(BalsaFrameEnums::READING_CONTENT, frame_->ParseState());
  ASSERT_EQ(9u, frame_->BytesSafeToSplice());
  checkpoint.Call(1);
  frame_->BytesSpliced(5);
  ASSERT_EQ(BalsaFrameEnums::READING_CONTENT, frame_->ParseState());
  ASSERT_EQ(4u, frame_->BytesSafeToSplice());
  checkpoint.Call(2);
  frame_->BytesSpliced(4);
  ASSERT_EQ(BalsaFrameEnums::MESSAGE_FULLY_READ, frame_->ParseState());

  ASSERT_TRUE(frame_->MessageFullyRead());
  ASSERT_FALSE(frame_->Error());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());
}

TEST_F(BalsaFrameTest, GetResponseBytesSplicedTooMany) {
  const char input[] = "HTTP/1.1 200 OK\r\n"
      "Content-type: text/plain\r\n"
      "Content-Length: 14\r\n\r\n"
      "hello";
  testing::MockFunction<void(int)> checkpoint;

  frame_->set_balsa_headers(frame_headers_.get());
  frame_->set_is_request(false);

  {
    InSequence s;
    EXPECT_CALL(*visitor_, ProcessResponseFirstLine(_, _, _, _, _, _, _, _));
    EXPECT_CALL(*visitor_, ProcessHeaderInput(_, _));
    EXPECT_CALL(*visitor_, ProcessHeaders(_));
    EXPECT_CALL(*visitor_, HeaderDone());
    EXPECT_CALL(checkpoint, Call(0));
    EXPECT_CALL(*visitor_, ProcessBodyInput(_, _));
    EXPECT_CALL(*visitor_, ProcessBodyData(_, _));
    EXPECT_CALL(checkpoint, Call(1));
    EXPECT_CALL(*visitor_, HandleBodyError(frame_.get()));
  }

  size_t read = frame_->ProcessInput(input, strlen(input));
  ASSERT_EQ(65u, read);
  ASSERT_EQ(BalsaFrameEnums::READING_CONTENT, frame_->ParseState());
  checkpoint.Call(0);
  read += frame_->ProcessInput(&input[read], strlen(input) - read);
  ASSERT_EQ(strlen(input), read);
  ASSERT_EQ(BalsaFrameEnums::READING_CONTENT, frame_->ParseState());
  ASSERT_EQ(9u, frame_->BytesSafeToSplice());
  checkpoint.Call(1);
  frame_->BytesSpliced(99);
  ASSERT_EQ(BalsaFrameEnums::PARSE_ERROR, frame_->ParseState());
  ASSERT_FALSE(frame_->MessageFullyRead());
  ASSERT_TRUE(frame_->Error());
  ASSERT_EQ(
      BalsaFrameEnums::CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT,
      frame_->ErrorCode());
  ASSERT_EQ(0u, frame_->BytesSafeToSplice());
}

}  // namespace

}  // namespace net
