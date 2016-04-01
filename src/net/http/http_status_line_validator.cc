// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_status_line_validator.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/string_util.h"

namespace net {

using base::StringPiece;

HttpStatusLineValidator::StatusLineStatus
HttpStatusLineValidator::ValidateStatusLine(const StringPiece& status_line) {
  std::vector<StringPiece> fields = base::SplitStringPiece(
      status_line, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  // Permissively split fields, meaning:
  // 1) Extra whitespace separating fields ignored
  // 2) Extra leading/trailing whitespace removed
  std::vector<StringPiece> loose_fields = base::SplitStringPiece(
      status_line, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  // Fields: HTTP-version status-code reason-phrase
  if (fields.empty() || loose_fields.empty())
    return STATUS_LINE_EMPTY;

  StatusLineStatus rv = CheckHttpVersionSyntax(fields[0]);
  if (rv != STATUS_LINE_OK)
    return rv;

  if (fields.size() < 2)
    return STATUS_LINE_MISSING_STATUS_CODE;

  rv = CheckStatusCodeSyntax(fields[1]);
  if (rv != STATUS_LINE_OK)
    return rv;

  // At this point the field splitting could be wrong, so check for extra
  // whitespace/padding on the result code.
  // Note that there is no such thing as "extra whitespace" on the
  // reason-phrase, since spaces are legal inside it.
  if (loose_fields[1] != fields[1])
    return STATUS_LINE_EXCESS_WHITESPACE;

  // An empty reason phrase will cause there to be only two fields in |fields|
  // but more than that in |loose_fields|.
  if (loose_fields.size() < 3)
    return STATUS_LINE_MISSING_REASON_PHRASE;
  return CheckReasonPhraseSyntax(fields, 2);
}

HttpStatusLineValidator::StatusLineStatus
HttpStatusLineValidator::CheckHttpVersionSyntax(const StringPiece& version) {
  static const char kProtoName[] = "HTTP";
  static const char kDigits[] = "0123456789";
  if (!base::StartsWith(version, kProtoName,
                        base::CompareCase::INSENSITIVE_ASCII)) {
    return STATUS_LINE_NOT_HTTP;
  }
  if (!base::StartsWith(version, kProtoName, base::CompareCase::SENSITIVE))
    return STATUS_LINE_HTTP_CASE_MISMATCH;
  // Okay, definitely "HTTP" at the start. Now check for the separating slash
  // and version number components:
  size_t slash = version.find('/');
  if (slash != strlen(kProtoName))
    return STATUS_LINE_HTTP_NO_VERSION;
  StringPiece rest = version.substr(slash + 1);
  size_t sep = rest.find('.');
  if (sep == StringPiece::npos) {
    return STATUS_LINE_INVALID_VERSION;
  }
  StringPiece major = rest.substr(0, sep);
  if (major.length() == 0)
    return STATUS_LINE_INVALID_VERSION;
  StringPiece minor = rest.substr(sep + 1);
  if (minor.length() == 0)
    return STATUS_LINE_INVALID_VERSION;
  if (major.find_first_not_of(kDigits) != major.npos ||
      minor.find_first_not_of(kDigits) != minor.npos) {
    return STATUS_LINE_INVALID_VERSION;
  }

  if (major.length() != 1 || minor.length() != 1)
    return STATUS_LINE_MULTI_DIGIT_VERSION;

  // It is now known that version looks like:
  //   HTTP/x.y
  // For single digits x and y.
  // Check that x == '1' and y == '0' or '1'
  if (major[0] != '1' || (minor[0] != '0' && minor[0] != '1')) {
    if (major[0] == '0' && minor[0] == '9')
      return STATUS_LINE_EXPLICIT_0_9;
    else
      return STATUS_LINE_UNKNOWN_VERSION;
  }
  return STATUS_LINE_OK;
}

HttpStatusLineValidator::StatusLineStatus
HttpStatusLineValidator::CheckStatusCodeSyntax(const StringPiece& status_code) {
  if (status_code.length() < 3)
    return STATUS_LINE_INVALID_STATUS_CODE;
  if (!isdigit(status_code[0]) || !isdigit(status_code[1]) ||
      !isdigit(status_code[2])) {
    return STATUS_LINE_INVALID_STATUS_CODE;
  }
  if (status_code.length() > 3)
    return STATUS_LINE_STATUS_CODE_TRAILING;
  // The only valid codes are 1xx through 5xx, see RFC 7231 S6
  if (status_code[0] < '1' || status_code[0] > '5')
    return STATUS_LINE_RESERVED_STATUS_CODE;
  return STATUS_LINE_OK;
}

HttpStatusLineValidator::StatusLineStatus
HttpStatusLineValidator::CheckReasonPhraseSyntax(
    const std::vector<StringPiece>& fields,
    size_t start_index) {
  for (size_t i = start_index; i < fields.size(); ++i) {
    for (size_t j = 0; j < fields[i].length(); ++j) {
      // VCHAR is any "visible" ASCII character, meaning any non-control
      // character, so >= ' ' but not DEL (\x7f).
      // obs-text is any character between \x80 and \xff.
      // HTAB is \t, SP is ' '
      char c = fields[i][j];
      if (c == '\x7f' || (c < ' ' && c != '\t'))
        return STATUS_LINE_REASON_DISALLOWED_CHARACTER;
    }
  }
  return STATUS_LINE_OK;
}

}  // namespace net
