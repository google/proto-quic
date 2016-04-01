// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Utility class that performs basic operations on header value tokens: parsing
// them out, checking for presense of certain tokens, and removing them.

#ifndef NET_TOOLS_BALSA_BALSA_HEADERS_TOKEN_UTILS_H_
#define NET_TOOLS_BALSA_BALSA_HEADERS_TOKEN_UTILS_H_

#include "base/strings/string_piece.h"
#include "net/tools/balsa/balsa_headers.h"

namespace net {

class BalsaHeadersTokenUtils {
 public:
  // All the functions below respect multiple header lines with the same key.

  // Checks whether the last header token matches a given value. Useful to
  // check the outer-most content or transfer-encoding, for example. In the
  // presence of multiple header lines with given key, the last token of the
  // last line is compared.
  static bool CheckHeaderForLastToken(const BalsaHeaders& headers,
                                      const base::StringPiece& key,
                                      const base::StringPiece& token);

  // Tokenizes header value for a given key. In the presence of multiple lines
  // with that key, all of them will be tokenized and tokens will be added to
  // the list in the order in which they are encountered.
  static void TokenizeHeaderValue(const BalsaHeaders& headers,
                                  const base::StringPiece& key,
                                  BalsaHeaders::HeaderTokenList* tokens);

  // Removes the last token from the header value. In the presence of multiple
  // header lines with given key, will remove the last token of the last line.
  // Can be useful if the last encoding has to be removed.
  static void RemoveLastTokenFromHeaderValue(const base::StringPiece& key,
                                             BalsaHeaders* headers);

  // Given a pointer to the beginning and the end of the header value
  // in some buffer, populates tokens list with beginning and end indices
  // of all tokens present in the value string.
  static void ParseTokenList(const char* start,
                             const char* end,
                             BalsaHeaders::HeaderTokenList* tokens);

 private:
  // Helper function to tokenize a header line once we have its description.
  static void TokenizeHeaderLine(
      const BalsaHeaders& headers,
      const BalsaHeaders::HeaderLineDescription& line,
      BalsaHeaders::HeaderTokenList* tokens);

  BalsaHeadersTokenUtils();  // Prohibit instantiation
};

}  // namespace net

#endif  // NET_TOOLS_BALSA_BALSA_HEADERS_TOKEN_UTILS_H_

