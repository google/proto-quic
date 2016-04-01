// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_TEST_TOOLS_TEST_TOOLS_HTTP_MESSAGE_H_
#define NET_TOOLS_QUIC_TEST_TOOLS_TEST_TOOLS_HTTP_MESSAGE_H_

#include <string>
#include <vector>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/tools/balsa/balsa_enums.h"
#include "net/tools/balsa/balsa_headers.h"

namespace net {
namespace test {

class HttpConstants {
 public:
  enum Version { HTTP_UNKNOWN = 0, HTTP_0_9, HTTP_1_0, HTTP_1_1 };

  enum Method {
    UNKNOWN_METHOD = 0,
    OPTIONS,
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    TRACE,
    CONNECT,

    MKCOL,
    UNLOCK,
  };
};

// Stripped down wrapper class which basically contains headers and a body.
class HTTPMessage {
 public:
  typedef HttpConstants::Version Version;
  typedef HttpConstants::Method Method;

  // Convenient functions to map strings into enums. The string passed in is
  // not assumed to be NULL-terminated.
  static Version StringToVersion(base::StringPiece str);
  static Method StringToMethod(base::StringPiece str);

  static const char* MethodToString(Method method);
  static const char* VersionToString(Version version);

  // Default constructor makes an empty HTTP/1.1 GET request. This is typically
  // used to construct a message that will be Initialize()-ed.
  HTTPMessage();

  // Build a request message
  HTTPMessage(Version version, Method request, const std::string& path);

  virtual ~HTTPMessage();

  const std::string& body() const { return body_; }

  // Adds a header line to the message.
  void AddHeader(const std::string& header, const std::string& value);

  // Removes a header line from the message.
  void RemoveHeader(const std::string& header);

  // A utility function which calls RemoveHeader followed by AddHeader.
  void ReplaceHeader(const std::string& header, const std::string& value);

  // Adds a body and the optional content-length header field (omitted to test
  // read until close test case). To generate a message that has a header field
  // of 0 content-length, call AddBody("", true).
  // Multiple calls to AddBody()/AddChunkedBody() has the effect of overwriting
  // the previous entry without warning.
  void AddBody(const std::string& body, bool add_content_length);

  bool has_complete_message() const { return has_complete_message_; }
  void set_has_complete_message(bool value) { has_complete_message_ = value; }

  // Do some basic http message consistency checks like:
  // - Valid transfer-encoding header
  // - Valid content-length header
  // - Messages we expect to be complete are complete.
  // This check can be disabled by setting skip_message_validation.
  void ValidateMessage() const;

  bool skip_message_validation() const { return skip_message_validation_; }
  void set_skip_message_validation(bool value) {
    skip_message_validation_ = value;
  }

  // Allow direct access to the body string.  This should be used with caution:
  // it will not update the request headers like AddBody and AddChunkedBody do.
  void set_body(const std::string& body) { body_ = body; }

  const BalsaHeaders* headers() const { return &headers_; }
  BalsaHeaders* headers() { return &headers_; }

 protected:
  BalsaHeaders headers_;

  std::string body_;  // the body with chunked framing/gzip compression

  bool is_request_;

  // True if the message should be considered complete during serialization.
  // Used by SPDY and Streamed RPC clients to decide wherever or not
  // to include fin flags and during message validation (if enabled).
  bool has_complete_message_;

  // Allows disabling message validation when creating test messages
  // that are intentionally invalid.
  bool skip_message_validation_;

 private:
  void InitializeFields();

  DISALLOW_COPY_AND_ASSIGN(HTTPMessage);
};

}  // namespace test
}  // namespace net

#endif  // NET_TOOLS_QUIC_TEST_TOOLS_TEST_TOOLS_HTTP_MESSAGE_H_
