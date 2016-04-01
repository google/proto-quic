// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/test_tools/http_message.h"

#include <vector>

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"

using base::StringPiece;
using std::string;
using std::vector;

namespace net {
namespace test {

namespace {

// const char kContentEncoding[] = "content-encoding";
const char kContentLength[] = "content-length";
const char kTransferCoding[] = "transfer-encoding";

// Both kHTTPVersionString and kMethodString arrays are constructed to match
// the enum values defined in Version and Method of HTTPMessage.
const char* const kHTTPVersionString[] = {"", "HTTP/0.9", "HTTP/1.0",
                                          "HTTP/1.1"};

const char* const kMethodString[] = {
    "",       "OPTIONS", "GET",     "HEAD",  "POST",   "PUT",
    "DELETE", "TRACE",   "CONNECT", "MKCOL", "UNLOCK",
};

// Returns true if the message represents a complete request or response.
// Messages are considered complete if:
// - Transfer-Encoding: chunked is present and message has a final chunk.
// - Content-Length header is present and matches the message body length.
// - Neither Transfer-Encoding nor Content-Length is present and message
//   is tagged as complete.
bool IsCompleteMessage(const HTTPMessage& message) {
  const BalsaHeaders* headers = message.headers();
  StringPiece content_length = headers->GetHeader(kContentLength);
  if (!content_length.empty()) {
    int parsed_content_length;
    if (!base::StringToInt(content_length, &parsed_content_length)) {
      return false;
    }
    return (message.body().size() == (uint)parsed_content_length);
  } else {
    // Assume messages without transfer coding or content-length are
    // tagged correctly.
    return message.has_complete_message();
  }
}

}  // namespace

HTTPMessage::Method HTTPMessage::StringToMethod(StringPiece str) {
  // Skip the first element of the array since it is empty string.
  for (unsigned long i = 1; i < arraysize(kMethodString); ++i) {
    if (strncmp(str.data(), kMethodString[i], str.length()) == 0) {
      return static_cast<HTTPMessage::Method>(i);
    }
  }
  return HttpConstants::UNKNOWN_METHOD;
}

HTTPMessage::Version HTTPMessage::StringToVersion(StringPiece str) {
  // Skip the first element of the array since it is empty string.
  for (unsigned long i = 1; i < arraysize(kHTTPVersionString); ++i) {
    if (strncmp(str.data(), kHTTPVersionString[i], str.length()) == 0) {
      return static_cast<HTTPMessage::Version>(i);
    }
  }
  return HttpConstants::HTTP_UNKNOWN;
}

const char* HTTPMessage::MethodToString(Method method) {
  CHECK_LT(static_cast<size_t>(method), arraysize(kMethodString));
  return kMethodString[method];
}

const char* HTTPMessage::VersionToString(Version version) {
  CHECK_LT(static_cast<size_t>(version), arraysize(kHTTPVersionString));
  return kHTTPVersionString[version];
}

HTTPMessage::HTTPMessage() : is_request_(true) {
  InitializeFields();
}

HTTPMessage::HTTPMessage(Version ver, Method request, const string& path)
    : is_request_(true) {
  InitializeFields();
  if (ver != HttpConstants::HTTP_0_9) {
    headers()->SetRequestVersion(VersionToString(ver));
  }
  headers()->SetRequestMethod(MethodToString(request));
  headers()->SetRequestUri(path);
}

HTTPMessage::~HTTPMessage() {}

void HTTPMessage::InitializeFields() {
  has_complete_message_ = true;
  skip_message_validation_ = false;
}

void HTTPMessage::AddHeader(const string& header, const string& value) {
  headers()->AppendHeader(header, value);
}

void HTTPMessage::RemoveHeader(const string& header) {
  headers()->RemoveAllOfHeader(header);
}

void HTTPMessage::ReplaceHeader(const string& header, const string& value) {
  headers()->ReplaceOrAppendHeader(header, value);
}

void HTTPMessage::AddBody(const string& body, bool add_content_length) {
  body_ = body;
  // Remove any transfer-encoding that was left by a previous body.
  RemoveHeader(kTransferCoding);
  if (add_content_length) {
    ReplaceHeader(kContentLength, base::SizeTToString(body.size()));
  } else {
    RemoveHeader(kContentLength);
  }
}

void HTTPMessage::ValidateMessage() const {
  if (skip_message_validation_) {
    return;
  }

  vector<StringPiece> transfer_encodings;
  headers()->GetAllOfHeader(kTransferCoding, &transfer_encodings);
  CHECK_GE(1ul, transfer_encodings.size());
  for (vector<StringPiece>::iterator it = transfer_encodings.begin();
       it != transfer_encodings.end(); ++it) {
    CHECK(base::EqualsCaseInsensitiveASCII("identity", *it) ||
          base::EqualsCaseInsensitiveASCII("chunked", *it))
        << *it;
  }

  vector<StringPiece> content_lengths;
  headers()->GetAllOfHeader(kContentLength, &content_lengths);
  CHECK_GE(1ul, content_lengths.size());

  CHECK_EQ(has_complete_message_, IsCompleteMessage(*this));
}

}  // namespace test
}  // namespace net
