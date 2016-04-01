// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/balsa/balsa_headers_token_utils.h"

namespace net {

inline void BalsaHeadersTokenUtils::TokenizeHeaderLine(
    const BalsaHeaders& headers,
    const BalsaHeaders::HeaderLineDescription& header_line,
    BalsaHeaders::HeaderTokenList* tokens) {
  CHECK(tokens);

  // Find where this line is stored
  const char* stream_begin = headers.GetPtr(header_line.buffer_base_idx);

  // Determine the boundaries of the value
  const char* value_begin = stream_begin + header_line.value_begin_idx;
  const char* line_end = stream_begin + header_line.last_char_idx;

  // Tokenize
  ParseTokenList(value_begin, line_end, tokens);
}

void BalsaHeadersTokenUtils::RemoveLastTokenFromHeaderValue(
    const base::StringPiece& key, BalsaHeaders* headers) {
  BalsaHeaders::HeaderLines::iterator it =
      headers->GetHeaderLinesIterator(key, headers->header_lines_.begin());
  if (it == headers->header_lines_.end()) {
    DLOG(WARNING) << "Attempting to remove last token from a non-existent "
                  << "header \"" << key << "\"";
    return;
  }

  // Find the last line with that key.
  BalsaHeaders::HeaderLines::iterator header_line;
  do {
    header_line = it;
    it = headers->GetHeaderLinesIterator(key, it + 1);
  }
  while (it != headers->header_lines_.end());

  // Tokenize just that line.
  BalsaHeaders::HeaderTokenList tokens;
  TokenizeHeaderLine(*headers, *header_line, &tokens);

  if (tokens.empty()) {
    DLOG(WARNING) << "Attempting to remove a token from an empty header value "
                  << "for header \"" << key << "\"";
    header_line->skip = true;  // remove the whole line
  } else if (tokens.size() == 1) {
    header_line->skip = true;  // remove the whole line
  } else {
    // Shrink the line size and leave the extra data in the buffer.
    const base::StringPiece& new_last_token = tokens[tokens.size() - 2];
    const char* last_char_address =
        new_last_token.data() + new_last_token.size() - 1;
    const char* stream_begin = headers->GetPtr(header_line->buffer_base_idx);

    header_line->last_char_idx = last_char_address - stream_begin + 1;
  }
}

bool BalsaHeadersTokenUtils::CheckHeaderForLastToken(
    const BalsaHeaders& headers,
    const base::StringPiece& key,
    const base::StringPiece& token) {
  BalsaHeaders::const_header_lines_key_iterator it =
      headers.GetIteratorForKey(key);
  if (it == headers.header_lines_key_end())
    return false;

  // Find the last line
  BalsaHeaders::const_header_lines_key_iterator header_line = it;
  do {
    header_line = it;
    ++it;
  }
  while (it != headers.header_lines_key_end());

  // Tokenize just that line
  BalsaHeaders::HeaderTokenList tokens;
  ParseTokenList(header_line->second.begin(), header_line->second.end(),
                 &tokens);

  return !tokens.empty() &&
         base::StartsWith(tokens.back(), token,
                          base::CompareCase::INSENSITIVE_ASCII);
}

void BalsaHeadersTokenUtils::TokenizeHeaderValue(
    const BalsaHeaders& headers,
    const base::StringPiece& key,
    BalsaHeaders::HeaderTokenList* tokens) {
  CHECK(tokens);
  tokens->clear();

  // We may have more then 1 line with the same header key. Tokenize them all
  // and stick all the tokens into the same list.
  for (BalsaHeaders::const_header_lines_key_iterator header_line =
           headers.GetIteratorForKey(key);
       header_line != headers.header_lines_key_end(); ++header_line) {
    ParseTokenList(header_line->second.begin(), header_line->second.end(),
                   tokens);
  }
}

void BalsaHeadersTokenUtils::ParseTokenList(
    const char* start,
    const char* end,
    BalsaHeaders::HeaderTokenList* tokens) {
  if (start == end) {
    return;
  }
  while (true) {
    // search for first nonwhitespace, non separator char.
    while (*start == ',' || *start <= ' ') {
      ++start;
      if (start == end) {
        return;
      }
    }
    // found. marked.
    const char* nws = start;

    // search for next whitspace or separator char.
    while (*start != ',' && *start > ' ') {
      ++start;
      if (start == end) {
        if (nws != start) {
          tokens->push_back(base::StringPiece(nws, start - nws));
        }
        return;
      }
    }
    tokens->push_back(base::StringPiece(nws, start - nws));
  }
}

}  // namespace net

