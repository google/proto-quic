// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_STATUS_LINE_VALIDATOR_H_
#define NET_HTTP_HTTP_STATUS_LINE_VALIDATOR_H_

#include <stddef.h>

#include <vector>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

class HttpStatusLineValidator {
 public:
  // RFC 7230 S3.1.2:
  //   status-line = HTTP-version SP status-code SP reason-phrase CRLF
  //   status-code = 3DIGIT
  //   reason-phrase = *( HTAB / SP / VCHAR / obs-text )
  // And from RFC 7230 S2.6:
  //   HTTP-version = HTTP-name "/" DIGIT "." DIGIT
  //   HTTP-name = "\x48\x54\x54\x50" ; ie, "HTTP" in uppercase
  enum StatusLineStatus {
    // No violations found.
    STATUS_LINE_OK = 0,
    // ""
    STATUS_LINE_EMPTY = 1,
    // "xyzzy"
    STATUS_LINE_NOT_HTTP = 2,
    // "HtTp/1.1 ..."
    STATUS_LINE_HTTP_CASE_MISMATCH = 3,
    // "HTTP" or "HTTP/"
    STATUS_LINE_HTTP_NO_VERSION = 4,
    // "HTTP/abc" or "HTTP/1" or "HTTP/1."
    STATUS_LINE_INVALID_VERSION = 5,
    // "HTTP/1.234 ..."
    STATUS_LINE_MULTI_DIGIT_VERSION = 6,
    // "HTTP/3.0 ..."
    STATUS_LINE_UNKNOWN_VERSION = 7,
    // "HTTP/0.9 ..."
    STATUS_LINE_EXPLICIT_0_9 = 8,
    // "HTTP/1.1"
    STATUS_LINE_MISSING_STATUS_CODE = 9,
    // "HTTP/1.1 abc"
    STATUS_LINE_INVALID_STATUS_CODE = 10,
    // "HTTP/1.1 123a"
    STATUS_LINE_STATUS_CODE_TRAILING = 11,
    // "HTTP/1.1 404", note that "HTTP/1.1 404 " is a valid empty reason phrase
    STATUS_LINE_MISSING_REASON_PHRASE = 12,
    // "HTTP/1.1 200 \x01"
    STATUS_LINE_REASON_DISALLOWED_CHARACTER = 13,
    // "HTTP/1.1   200 OK"
    STATUS_LINE_EXCESS_WHITESPACE = 14,
    // "HTTP/1.1 600 OK"
    STATUS_LINE_RESERVED_STATUS_CODE = 15,

    STATUS_LINE_MAX
  };

  // Checks for violations of the RFC 7230 S3.1.2 status-line grammar, and
  // returns the first violation found, or STATUS_LINE_OK if the status line
  // looks conforming.
  static StatusLineStatus NET_EXPORT_PRIVATE ValidateStatusLine(
      const base::StringPiece& status_line);

 private:
  static StatusLineStatus CheckHttpVersionSyntax(
      const base::StringPiece& version);
  static StatusLineStatus CheckStatusCodeSyntax(
      const base::StringPiece& status_code);
  // Checks |fields| against the reason-phrase syntax in RFC 7230 S3.1.2, ie:
  //   reason-phrase = *( HTAB / SP / VCHAR / obs-text )
  // Note that the HTTP stream parser ignores the reason-phrase entirely, so
  // this check is needlessly pedantic.
  static StatusLineStatus CheckReasonPhraseSyntax(
      const std::vector<base::StringPiece>& fields,
      size_t start_index);

  DISALLOW_IMPLICIT_CONSTRUCTORS(HttpStatusLineValidator);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_STATUS_LINE_VALIDATOR_H_
