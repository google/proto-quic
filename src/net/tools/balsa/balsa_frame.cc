// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/balsa/balsa_frame.h"

// Visual C++ defines _M_IX86_FP as 2 if the /arch:SSE2 compiler option is
// specified.
#if !defined(__SSE2__) && _M_IX86_FP == 2
#define __SSE2__ 1
#endif

#include <assert.h>
#if __SSE2__
#include <emmintrin.h>
#endif  // __SSE2__

#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "net/tools/balsa/balsa_enums.h"
#include "net/tools/balsa/balsa_headers.h"
#include "net/tools/balsa/balsa_visitor_interface.h"
#include "net/tools/balsa/buffer_interface.h"
#include "net/tools/balsa/simple_buffer.h"
#include "net/tools/balsa/string_piece_utils.h"

#if defined(COMPILER_MSVC)
#include <intrin.h>
#include <string.h>

#pragma intrinsic(_BitScanForward)

static int ffs(int i) {
  unsigned long index;
  return _BitScanForward(&index, i) ? index + 1 : 0;
}

#define strncasecmp _strnicmp
#else
#include <strings.h>
#endif

namespace net {

// Constants holding some header names for headers which can affect the way the
// HTTP message is framed, and so must be processed specially:
static const char kContentLength[] = "content-length";
static const size_t kContentLengthSize = sizeof(kContentLength) - 1;
static const char kTransferEncoding[] = "transfer-encoding";
static const size_t kTransferEncodingSize = sizeof(kTransferEncoding) - 1;

BalsaFrame::BalsaFrame()
    : last_char_was_slash_r_(false),
      saw_non_newline_char_(false),
      start_was_space_(true),
      chunk_length_character_extracted_(false),
      is_request_(true),
      request_was_head_(false),
      max_header_length_(16 * 1024),
      max_request_uri_length_(2048),
      visitor_(&do_nothing_visitor_),
      chunk_length_remaining_(0),
      content_length_remaining_(0),
      last_slash_n_loc_(NULL),
      last_recorded_slash_n_loc_(NULL),
      last_slash_n_idx_(0),
      term_chars_(0),
      parse_state_(BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE),
      last_error_(BalsaFrameEnums::NO_ERROR),
      headers_(NULL) {
}

BalsaFrame::~BalsaFrame() {}

void BalsaFrame::Reset() {
  last_char_was_slash_r_ = false;
  saw_non_newline_char_ = false;
  start_was_space_ = true;
  chunk_length_character_extracted_ = false;
  // is_request_ = true;               // not reset between messages.
  // request_was_head_ = false;        // not reset between messages.
  // max_header_length_ = 4096;        // not reset between messages.
  // max_request_uri_length_ = 2048;   // not reset between messages.
  // visitor_ = &do_nothing_visitor_;  // not reset between messages.
  chunk_length_remaining_ = 0;
  content_length_remaining_ = 0;
  last_slash_n_loc_ = NULL;
  last_recorded_slash_n_loc_ = NULL;
  last_slash_n_idx_ = 0;
  term_chars_ = 0;
  parse_state_ = BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE;
  last_error_ = BalsaFrameEnums::NO_ERROR;
  lines_.clear();
  if (headers_ != NULL) {
    headers_->Clear();
  }
}

const char* BalsaFrameEnums::ParseStateToString(
    BalsaFrameEnums::ParseState error_code) {
  switch (error_code) {
    case PARSE_ERROR:
      return "PARSE_ERROR";
    case READING_HEADER_AND_FIRSTLINE:
      return "READING_HEADER_AND_FIRSTLINE";
    case READING_CHUNK_LENGTH:
      return "READING_CHUNK_LENGTH";
    case READING_CHUNK_EXTENSION:
      return "READING_CHUNK_EXTENSION";
    case READING_CHUNK_DATA:
      return "READING_CHUNK_DATA";
    case READING_CHUNK_TERM:
      return "READING_CHUNK_TERM";
    case READING_LAST_CHUNK_TERM:
      return "READING_LAST_CHUNK_TERM";
    case READING_TRAILER:
      return "READING_TRAILER";
    case READING_UNTIL_CLOSE:
      return "READING_UNTIL_CLOSE";
    case READING_CONTENT:
      return "READING_CONTENT";
    case MESSAGE_FULLY_READ:
      return "MESSAGE_FULLY_READ";
    case NUM_STATES:
      return "UNKNOWN_STATE";
  }
  return "UNKNOWN_STATE";
}

const char* BalsaFrameEnums::ErrorCodeToString(
    BalsaFrameEnums::ErrorCode error_code) {
  switch (error_code) {
    case NO_ERROR:
      return "NO_ERROR";
    case NO_STATUS_LINE_IN_RESPONSE:
      return "NO_STATUS_LINE_IN_RESPONSE";
    case NO_REQUEST_LINE_IN_REQUEST:
      return "NO_REQUEST_LINE_IN_REQUEST";
    case FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION:
      return "FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION";
    case FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD:
      return "FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD";
    case FAILED_TO_FIND_WS_AFTER_RESPONSE_STATUSCODE:
      return "FAILED_TO_FIND_WS_AFTER_RESPONSE_STATUSCODE";
    case FAILED_TO_FIND_WS_AFTER_REQUEST_REQUEST_URI:
      return "FAILED_TO_FIND_WS_AFTER_REQUEST_REQUEST_URI";
    case FAILED_TO_FIND_NL_AFTER_RESPONSE_REASON_PHRASE:
      return "FAILED_TO_FIND_NL_AFTER_RESPONSE_REASON_PHRASE";
    case FAILED_TO_FIND_NL_AFTER_REQUEST_HTTP_VERSION:
      return "FAILED_TO_FIND_NL_AFTER_REQUEST_HTTP_VERSION";
    case FAILED_CONVERTING_STATUS_CODE_TO_INT:
      return "FAILED_CONVERTING_STATUS_CODE_TO_INT";
    case REQUEST_URI_TOO_LONG:
      return "REQUEST_URI_TOO_LONG";
    case HEADERS_TOO_LONG:
      return "HEADERS_TOO_LONG";
    case UNPARSABLE_CONTENT_LENGTH:
      return "UNPARSABLE_CONTENT_LENGTH";
    case MAYBE_BODY_BUT_NO_CONTENT_LENGTH:
      return "MAYBE_BODY_BUT_NO_CONTENT_LENGTH";
    case REQUIRED_BODY_BUT_NO_CONTENT_LENGTH:
      return "REQUIRED_BODY_BUT_NO_CONTENT_LENGTH";
    case HEADER_MISSING_COLON:
      return "HEADER_MISSING_COLON";
    case INVALID_CHUNK_LENGTH:
      return "INVALID_CHUNK_LENGTH";
    case CHUNK_LENGTH_OVERFLOW:
      return "CHUNK_LENGTH_OVERFLOW";
    case CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO:
      return "CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO";
    case CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT:
      return "CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT";
    case MULTIPLE_CONTENT_LENGTH_KEYS:
      return "MULTIPLE_CONTENT_LENGTH_KEYS";
    case MULTIPLE_TRANSFER_ENCODING_KEYS:
      return "MULTIPLE_TRANSFER_ENCODING_KEYS";
    case UNKNOWN_TRANSFER_ENCODING:
      return "UNKNOWN_TRANSFER_ENCODING";
    case INVALID_HEADER_FORMAT:
      return "INVALID_HEADER_FORMAT";
    case INTERNAL_LOGIC_ERROR:
      return "INTERNAL_LOGIC_ERROR";
    case NUM_ERROR_CODES:
      return "UNKNOWN_ERROR";
  }
  return "UNKNOWN_ERROR";
}

// Summary:
//     Parses the first line of either a request or response.
//     Note that in the case of a detected warning, error_code will be set
//   but the function will not return false.
//     Exactly zero or one warning or error (but not both) may be detected
//   by this function.
//     Note that this function will not write the data of the first-line
//   into the header's buffer (that should already have been done elsewhere).
//
// Pre-conditions:
//     begin != end
//     *begin should be a character which is > ' '. This implies that there
//   is at least one non-whitespace characters between [begin, end).
//   headers is a valid pointer to a BalsaHeaders class.
//     error_code is a valid pointer to a BalsaFrameEnums::ErrorCode value.
//     Entire first line must exist between [begin, end)
//     Exactly zero or one newlines -may- exist between [begin, end)
//     [begin, end) should exist in the header's buffer.
//
// Side-effects:
//   headers will be modified
//   error_code may be modified if either a warning or error is detected
//
// Returns:
//   True if no error (as opposed to warning) is detected.
//   False if an error (as opposed to warning) is detected.

//
// If there is indeed non-whitespace in the line, then the following
// will take care of this for you:
//  while (*begin <= ' ') ++begin;
//  ProcessFirstLine(begin, end, is_request, &headers, &error_code);
//
bool ParseHTTPFirstLine(const char* begin,
                        const char* end,
                        bool is_request,
                        size_t max_request_uri_length,
                        BalsaHeaders* headers,
                        BalsaFrameEnums::ErrorCode* error_code) {
  const char* current = begin;
  // HTTP firstlines all have the following structure:
  //  LWS         NONWS  LWS    NONWS   LWS    NONWS   NOTCRLF  CRLF
  //  [\t \r\n]+ [^\t ]+ [\t ]+ [^\t ]+ [\t ]+ [^\t ]+ [^\r\n]+ "\r\n"
  //  ws1        nws1    ws2    nws2    ws3    nws3             ws4
  //  |          [-------)      [-------)      [----------------)
  //    REQ:     method         request_uri    version
  //   RESP:     version        statuscode     reason
  //
  //   The first NONWS->LWS component we'll call firstline_a.
  //   The second firstline_b, and the third firstline_c.
  //
  //   firstline_a goes from nws1 to (but not including) ws2
  //   firstline_b goes from nws2 to (but not including) ws3
  //   firstline_c goes from nws3 to (but not including) ws4
  //
  // In the code:
  //    ws1 == whitespace_1_idx_
  //   nws1 == non_whitespace_1_idx_
  //    ws2 == whitespace_2_idx_
  //   nws2 == non_whitespace_2_idx_
  //    ws3 == whitespace_3_idx_
  //   nws3 == non_whitespace_3_idx_
  //    ws4 == whitespace_4_idx_

  // Kill all whitespace (including '\r\n') at the end of the line.
  --end;
  if (*end != '\n') {
    *error_code = BalsaFrameEnums::INTERNAL_LOGIC_ERROR;
    LOG(DFATAL) << "INTERNAL_LOGIC_ERROR Headers: \n"
                << headers->OriginalHeadersForDebugging();
    return false;
  }
  while (begin < end && *end <= ' ') {
    --end;
  }
  DCHECK(*end != '\n');
  if (*end == '\n') {
    *error_code = BalsaFrameEnums::INTERNAL_LOGIC_ERROR;
    LOG(DFATAL) << "INTERNAL_LOGIC_ERROR Headers: \n"
                << headers->OriginalHeadersForDebugging();
    return false;
  }
  ++end;

  // The two following statements should not be possible.
  if (end == begin) {
    *error_code = BalsaFrameEnums::INTERNAL_LOGIC_ERROR;
    LOG(DFATAL) << "INTERNAL_LOGIC_ERROR Headers: \n"
                << headers->OriginalHeadersForDebugging();
    return false;
  }

  // whitespace_1_idx_
  headers->whitespace_1_idx_ = current - begin;
  // This loop is commented out as it is never used in current code.  This is
  // true only because we don't begin parsing the headers at all until we've
  // encountered a non whitespace character at the beginning of the stream, at
  // which point we begin our demarcation of header-start.  If we did -not- do
  // this (for instance, only looked for [\r\n] instead of (< ' ')), this loop
  // would be necessary for the proper functioning of this parsing.
  // This is left here as this function may (in the future) be refactored out
  // of the BalsaFrame class so that it may be shared between code in
  // BalsaFrame and BalsaHeaders (where it would be used in some variant of the
  // set_first_line() function (at which point it would be necessary).
#if 0
  while (*current <= ' ') {
    ++current;
  }
#endif
  // non_whitespace_1_idx_
  headers->non_whitespace_1_idx_ = current - begin;
  do {
    // The first time through, we're guaranteed that the current character
    // won't be a whitespace (else the loop above wouldn't have terminated).
    // That implies that we're guaranteed to get at least one non-whitespace
    // character if we get into this loop at all.
    ++current;
    if (current == end) {
      headers->whitespace_2_idx_ = current - begin;
      headers->non_whitespace_2_idx_ = current - begin;
      headers->whitespace_3_idx_ = current - begin;
      headers->non_whitespace_3_idx_ = current - begin;
      headers->whitespace_4_idx_ = current - begin;
      // FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD   for request
      // FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION for response
      *error_code =
        static_cast<BalsaFrameEnums::ErrorCode>(
            BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION +
            is_request);
      if (!is_request) {  // FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION
        return false;
      }
      goto output_exhausted;
    }
  } while (*current > ' ');
  // whitespace_2_idx_
  headers->whitespace_2_idx_ = current - begin;
  do {
    ++current;
    // Note that due to the loop which consumes all of the whitespace
    // at the end of the line, current can never == end while in this function.
  } while (*current <= ' ');
  // non_whitespace_2_idx_
  headers->non_whitespace_2_idx_ = current - begin;
  do {
    ++current;
    if (current == end) {
      headers->whitespace_3_idx_ = current - begin;
      headers->non_whitespace_3_idx_ = current - begin;
      headers->whitespace_4_idx_ = current - begin;
      // FAILED_TO_FIND_START_OF_REQUEST_REQUEST_URI for request
      // FAILED_TO_FIND_START_OF_RESPONSE_STATUSCODE for response
      *error_code =
        static_cast<BalsaFrameEnums::ErrorCode>(
            BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_RESPONSE_STATUSCODE
                                 + is_request);
      goto output_exhausted;
    }
  } while (*current > ' ');
  // whitespace_3_idx_
  headers->whitespace_3_idx_ = current - begin;
  do {
    ++current;
    // Note that due to the loop which consumes all of the whitespace
    // at the end of the line, current can never == end while in this function.
  } while (*current <= ' ');
  // non_whitespace_3_idx_
  headers->non_whitespace_3_idx_ = current - begin;
  headers->whitespace_4_idx_ = end - begin;

 output_exhausted:
  // Note that we don't fail the parse immediately when parsing of the
  // firstline fails.  Depending on the protocol type, we may want to accept
  // a firstline with only one or two elements, e.g., for HTTP/0.9:
  //   GET\r\n
  // or
  //   GET /\r\n
  // should be parsed without issue (though the visitor should know that
  // parsing the entire line was not exactly as it should be).
  //
  // Eventually, these errors may be removed alltogether, as the visitor can
  // detect them on its own by examining the size of the various fields.
  // headers->set_first_line(non_whitespace_1_idx_, current);

  if (is_request) {
    if ((headers->whitespace_3_idx_ - headers->non_whitespace_2_idx_) >
        max_request_uri_length) {
      // For requests, we need at least the method.  We could assume that a
      // blank URI means "/".  If version isn't stated, it should be assumed
      // to be HTTP/0.9 by the visitor.
      *error_code = BalsaFrameEnums::REQUEST_URI_TOO_LONG;
      return false;
    }
  } else {
    headers->parsed_response_code_ = 0;
    {
      const char* parsed_response_code_current =
        begin + headers->non_whitespace_2_idx_;
      const char* parsed_response_code_end = begin + headers->whitespace_3_idx_;
      const size_t kMaxDiv10 = std::numeric_limits<size_t>::max() / 10;

      // Convert a string of [0-9]* into an int.
      // Note that this allows for the conversion of response codes which
      // are outside the bounds of normal HTTP response codes (no checking
      // is done to ensure that these are valid-- they're merely parsed)!
      while (parsed_response_code_current < parsed_response_code_end) {
        if (*parsed_response_code_current < '0' ||
            *parsed_response_code_current > '9') {
          *error_code = BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT;
          return false;
        }
        size_t status_code_x_10 = headers->parsed_response_code_ * 10;
        uint8_t c = *parsed_response_code_current - '0';
        if ((headers->parsed_response_code_ > kMaxDiv10) ||
            (std::numeric_limits<size_t>::max() - status_code_x_10) < c) {
          // overflow.
          *error_code = BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT;
          return false;
        }
        headers->parsed_response_code_ = status_code_x_10 + c;
        ++parsed_response_code_current;
      }
    }
  }
  return true;
}

// begin - beginning of the firstline
// end - end of the firstline
//
// A precondition for this function is that there is non-whitespace between
// [begin, end). If this precondition is not met, the function will not perform
// as expected (and bad things may happen, and it will eat your first, second,
// and third unborn children!).
//
// Another precondition for this function is that [begin, end) includes
// at most one newline, which must be at the end of the line.
void BalsaFrame::ProcessFirstLine(const char* begin, const char* end) {
  BalsaFrameEnums::ErrorCode previous_error = last_error_;
  if (!ParseHTTPFirstLine(begin,
                          end,
                          is_request_,
                          max_request_uri_length_,
                          headers_,
                          &last_error_)) {
    parse_state_ = BalsaFrameEnums::PARSE_ERROR;
    visitor_->HandleHeaderError(this);
    return;
  }
  if (previous_error != last_error_) {
    visitor_->HandleHeaderWarning(this);
  }

  if (is_request_) {
    size_t version_length =
        headers_->whitespace_4_idx_ - headers_->non_whitespace_3_idx_;
    visitor_->ProcessRequestFirstLine(
        begin + headers_->non_whitespace_1_idx_,
        headers_->whitespace_4_idx_ - headers_->non_whitespace_1_idx_,
        begin + headers_->non_whitespace_1_idx_,
        headers_->whitespace_2_idx_ - headers_->non_whitespace_1_idx_,
        begin + headers_->non_whitespace_2_idx_,
        headers_->whitespace_3_idx_ - headers_->non_whitespace_2_idx_,
        begin + headers_->non_whitespace_3_idx_,
        version_length);
    if (version_length == 0)
      parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
  } else {
    visitor_->ProcessResponseFirstLine(
        begin + headers_->non_whitespace_1_idx_,
        headers_->whitespace_4_idx_ - headers_->non_whitespace_1_idx_,
        begin + headers_->non_whitespace_1_idx_,
        headers_->whitespace_2_idx_ - headers_->non_whitespace_1_idx_,
        begin + headers_->non_whitespace_2_idx_,
        headers_->whitespace_3_idx_ - headers_->non_whitespace_2_idx_,
        begin + headers_->non_whitespace_3_idx_,
        headers_->whitespace_4_idx_ - headers_->non_whitespace_3_idx_);
  }
}

// 'stream_begin' points to the first character of the headers buffer.
// 'line_begin' points to the first character of the line.
// 'current' points to a char which is ':'.
// 'line_end' points to the position of '\n' + 1.
// 'line_begin' points to the position of first character of line.
void BalsaFrame::CleanUpKeyValueWhitespace(
    const char* stream_begin,
    const char* line_begin,
    const char* current,
    const char* line_end,
    HeaderLineDescription* current_header_line) {
  const char* colon_loc = current;
  DCHECK_LT(colon_loc, line_end);
  DCHECK_EQ(':', *colon_loc);
  DCHECK_EQ(':', *current);
  DCHECK_GE(' ', *line_end)
    << "\"" << std::string(line_begin, line_end) << "\"";

  // TODO(fenix): Investigate whether or not the bounds tests in the
  // while loops here are redundant, and if so, remove them.
  --current;
  while (current > line_begin && *current <= ' ') --current;
  current += (current != colon_loc);
  current_header_line->key_end_idx = current - stream_begin;

  current = colon_loc;
  DCHECK_EQ(':', *current);
  ++current;
  while (current < line_end && *current <= ' ') ++current;
  current_header_line->value_begin_idx = current - stream_begin;

  DCHECK_GE(current_header_line->key_end_idx,
            current_header_line->first_char_idx);
  DCHECK_GE(current_header_line->value_begin_idx,
            current_header_line->key_end_idx);
  DCHECK_GE(current_header_line->last_char_idx,
            current_header_line->value_begin_idx);
}

inline void BalsaFrame::FindColonsAndParseIntoKeyValue() {
  DCHECK(!lines_.empty());
  const char* stream_begin = headers_->OriginalHeaderStreamBegin();
  // The last line is always just a newline (and is uninteresting).
  const Lines::size_type lines_size_m1 = lines_.size() - 1;
#if __SSE2__
  const __m128i colons = _mm_set1_epi8(':');
  const char* header_lines_end_m16 = headers_->OriginalHeaderStreamEnd() - 16;
#endif  // __SSE2__
  const char* current = stream_begin + lines_[1].first;
  // This code is a bit more subtle than it may appear at first glance.
  // This code looks for a colon in the current line... but it also looks
  // beyond the current line. If there is no colon in the current line, then
  // for each subsequent line (until the colon which -has- been found is
  // associated with a line), no searching for a colon will be performed. In
  // this way, we minimize the amount of bytes we have scanned for a colon.
  for (Lines::size_type i = 1; i < lines_size_m1;) {
    const char* line_begin = stream_begin + lines_[i].first;

    // Here we handle possible continuations.  Note that we do not replace
    // the '\n' in the line before a continuation (at least, as of now),
    // which implies that any code which looks for a value must deal with
    // "\r\n", etc -within- the line (and not just at the end of it).
    for (++i; i < lines_size_m1; ++i) {
      const char c = *(stream_begin + lines_[i].first);
      if (c > ' ') {
        // Not a continuation, so stop.  Note that if the 'original' i = 1,
        // and the next line is not a continuation, we'll end up with i = 2
        // when we break. This handles the incrementing of i for the outer
        // loop.
        break;
      }
    }
    const char* line_end = stream_begin + lines_[i - 1].second;
    DCHECK_LT(line_begin - stream_begin, line_end - stream_begin);

    // We cleanup the whitespace at the end of the line before doing anything
    // else of interest as it allows us to do nothing when irregularly formatted
    // headers are parsed (e.g. those with only keys, only values, or no colon).
    //
    // We're guaranteed to have *line_end > ' ' while line_end >= line_begin.
    --line_end;
    DCHECK_EQ('\n', *line_end)
      << "\"" << std::string(line_begin, line_end) << "\"";
    while (*line_end <= ' ' && line_end > line_begin) {
      --line_end;
    }
    ++line_end;
    DCHECK_GE(' ', *line_end);
    DCHECK_LT(line_begin, line_end);

    // We use '0' for the block idx, because we're always writing to the first
    // block from the framer (we do this because the framer requires that the
    // entire header sequence be in a contiguous buffer).
    headers_->header_lines_.push_back(
        HeaderLineDescription(line_begin - stream_begin,
                              line_end - stream_begin,
                              line_end - stream_begin,
                              line_end - stream_begin,
                              0));
    if (current >= line_end) {
      last_error_ = BalsaFrameEnums::HEADER_MISSING_COLON;
      visitor_->HandleHeaderWarning(this);
      // Then the next colon will not be found within this header line-- time
      // to try again with another header-line.
      continue;
    } else if (current < line_begin) {
      // When this condition is true, the last detected colon was part of a
      // previous line.  We reset to the beginning of the line as we don't care
      // about the presence of any colon before the beginning of the current
      // line.
      current = line_begin;
    }
#if __SSE2__
    while (current < header_lines_end_m16) {
      __m128i header_bytes =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(current));
      __m128i colon_cmp = _mm_cmpeq_epi8(header_bytes, colons);
      int colon_msk = _mm_movemask_epi8(colon_cmp);
      if (colon_msk == 0) {
        current += 16;
        continue;
      }
      current += (ffs(colon_msk) - 1);
      if (current > line_end) {
        break;
      }
      goto found_colon;
    }
#endif  // __SSE2__
    for (; current < line_end; ++current) {
      if (*current != ':') {
        continue;
      }
      goto found_colon;
    }
    // If we've gotten to here, then there was no colon
    // in the line. The arguments we passed into the construction
    // for the HeaderLineDescription object should be OK-- it assumes
    // that the entire content is 'key' by default (which is true, as
    // there was no colon, there can be no value). Note that this is a
    // construct which is technically not allowed by the spec.
    last_error_ = BalsaFrameEnums::HEADER_MISSING_COLON;
    visitor_->HandleHeaderWarning(this);
    continue;
 found_colon:
    DCHECK_EQ(*current, ':');
    DCHECK_LE(current - stream_begin, line_end - stream_begin);
    DCHECK_LE(stream_begin - stream_begin, current - stream_begin);

    HeaderLineDescription& current_header_line = headers_->header_lines_.back();
    current_header_line.key_end_idx = current - stream_begin;
    current_header_line.value_begin_idx = current_header_line.key_end_idx;
    if (current < line_end) {
      ++current_header_line.key_end_idx;

      CleanUpKeyValueWhitespace(stream_begin,
                                line_begin,
                                current,
                                line_end,
                                &current_header_line);
    }
  }
}

void BalsaFrame::ProcessContentLengthLine(
    HeaderLines::size_type line_idx,
    BalsaHeadersEnums::ContentLengthStatus* status,
    size_t* length) {
  const HeaderLineDescription& header_line = headers_->header_lines_[line_idx];
  const char* stream_begin = headers_->OriginalHeaderStreamBegin();
  const char* line_end = stream_begin + header_line.last_char_idx;
  const char* value_begin = (stream_begin + header_line.value_begin_idx);

  if (value_begin >= line_end) {
    // There is no non-whitespace value data.
#if DEBUGFRAMER
      LOG(INFO) << "invalid content-length -- no non-whitespace value data";
#endif
    *status = BalsaHeadersEnums::INVALID_CONTENT_LENGTH;
    return;
  }

  *length = 0;
  while (value_begin < line_end) {
    if (*value_begin < '0' || *value_begin > '9') {
      // bad! content-length found, and couldn't parse all of it!
      *status = BalsaHeadersEnums::INVALID_CONTENT_LENGTH;
#if DEBUGFRAMER
      LOG(INFO) << "invalid content-length - non numeric character detected";
#endif  // DEBUGFRAMER
      return;
    }
    const size_t kMaxDiv10 = std::numeric_limits<size_t>::max() / 10;
    size_t length_x_10 = *length * 10;
    const unsigned char c = *value_begin - '0';
    if (*length > kMaxDiv10 ||
        (std::numeric_limits<size_t>::max() - length_x_10) < c) {
      *status = BalsaHeadersEnums::CONTENT_LENGTH_OVERFLOW;
#if DEBUGFRAMER
      LOG(INFO) << "content-length overflow";
#endif  // DEBUGFRAMER
      return;
    }
    *length = length_x_10 + c;
    ++value_begin;
  }
#if DEBUGFRAMER
  LOG(INFO) << "content_length parsed: " << *length;
#endif  // DEBUGFRAMER
  *status = BalsaHeadersEnums::VALID_CONTENT_LENGTH;
}

void BalsaFrame::ProcessTransferEncodingLine(HeaderLines::size_type line_idx) {
  const HeaderLineDescription& header_line = headers_->header_lines_[line_idx];
  const char* stream_begin = headers_->OriginalHeaderStreamBegin();
  const char* line_end = stream_begin + header_line.last_char_idx;
  const char* value_begin = stream_begin + header_line.value_begin_idx;
  size_t value_length = line_end - value_begin;

  if ((value_length == 7) &&
      !strncasecmp(value_begin, "chunked", 7)) {
    headers_->transfer_encoding_is_chunked_ = true;
  } else if ((value_length == 8) &&
      !strncasecmp(value_begin, "identity", 8)) {
    headers_->transfer_encoding_is_chunked_ = false;
  } else {
    last_error_ = BalsaFrameEnums::UNKNOWN_TRANSFER_ENCODING;
    parse_state_ = BalsaFrameEnums::PARSE_ERROR;
    visitor_->HandleHeaderError(this);
    return;
  }
}

namespace {
bool SplitStringPiece(base::StringPiece original, char delim,
                      base::StringPiece* before, base::StringPiece* after) {
  const char* p = original.data();
  const char* end = p + original.size();

  while (p != end) {
    if (*p == delim) {
      ++p;
    } else {
      const char* start = p;
      while (++p != end && *p != delim) {
        // Skip to the next occurence of the delimiter.
      }
      *before = base::StringPiece(start, p - start);
      if (p != end)
        *after = base::StringPiece(p + 1, end - (p + 1));
      else
        *after = base::StringPiece("");
      *before = base::TrimWhitespaceASCII(*before, base::TRIM_ALL);
      *after = base::TrimWhitespaceASCII(*after, base::TRIM_ALL);
      return true;
    }
  }

  *before = original;
  *after = "";
  return false;
}

// TODO(phython): Fix this function to properly deal with quoted values.
// E.g. ";;foo", "\";;\"", or \"aa;
// The last example, the semi-colon is a separator between extensions.
void ProcessChunkExtensionsManual(base::StringPiece all_extensions,
                                  BalsaHeaders* extensions) {
  base::StringPiece extension;
  base::StringPiece remaining;
  all_extensions = base::TrimWhitespaceASCII(all_extensions, base::TRIM_ALL);
  SplitStringPiece(all_extensions, ';', &extension, &remaining);
  while (!extension.empty()) {
    base::StringPiece key;
    base::StringPiece value;
    SplitStringPiece(extension, '=', &key, &value);
    if (!value.empty()) {
      // Strip quotation marks if they exist.
      if (!value.empty() && value.front() == '"')
        value.remove_prefix(1);
      if (!value.empty() && value.back() == '"')
        value.remove_suffix(1);
    }

    extensions->AppendHeader(key, value);

    remaining = base::TrimWhitespaceASCII(remaining, base::TRIM_ALL);
    SplitStringPiece(remaining, ';', &extension, &remaining);
  }
}

}  // anonymous namespace

void BalsaFrame::ProcessChunkExtensions(const char* input, size_t size,
                                        BalsaHeaders* extensions) {
  ProcessChunkExtensionsManual(base::StringPiece(input, size), extensions);
}

void BalsaFrame::ProcessHeaderLines() {
  HeaderLines::size_type content_length_idx = 0;
  HeaderLines::size_type transfer_encoding_idx = 0;

  DCHECK(!lines_.empty());
#if DEBUGFRAMER
  LOG(INFO) << "******@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@**********\n";
#endif  // DEBUGFRAMER

  // There is no need to attempt to process headers if no header lines exist.
  // There are at least two lines in the message which are not header lines.
  // These two non-header lines are the first line of the message, and the
  // last line of the message (which is an empty line).
  // Thus, we test to see if we have more than two lines total before attempting
  // to parse any header lines.
  if (lines_.size() > 2) {
    const char* stream_begin = headers_->OriginalHeaderStreamBegin();

    // Then, for the rest of the header data, we parse these into key-value
    // pairs.
    FindColonsAndParseIntoKeyValue();
    // At this point, we've parsed all of the headers.  Time to look for those
    // headers which we require for framing.
    const HeaderLines::size_type
      header_lines_size = headers_->header_lines_.size();
    for (HeaderLines::size_type i = 0; i < header_lines_size; ++i) {
      const HeaderLineDescription& current_header_line =
        headers_->header_lines_[i];
      const char* key_begin =
        (stream_begin + current_header_line.first_char_idx);
      const char* key_end = (stream_begin + current_header_line.key_end_idx);
      const size_t key_len = key_end - key_begin;
      const char c = *key_begin;
#if DEBUGFRAMER
      LOG(INFO) << "[" << i << "]: " << std::string(key_begin, key_len)
                << " c: '" << c << "' key_len: " << key_len;
#endif  // DEBUGFRAMER
      // If a header begins with either lowercase or uppercase 'c' or 't', then
      // the header may be one of content-length, connection, content-encoding
      // or transfer-encoding. These headers are special, as they change the way
      // that the message is framed, and so the framer is required to search
      // for them.


      if (c == 'c' || c == 'C') {
        if ((key_len == kContentLengthSize) &&
            0 == strncasecmp(key_begin, kContentLength, kContentLengthSize)) {
          BalsaHeadersEnums::ContentLengthStatus content_length_status =
            BalsaHeadersEnums::NO_CONTENT_LENGTH;
          size_t length = 0;
          ProcessContentLengthLine(i, &content_length_status, &length);
          if (content_length_idx != 0) {  // then we've already seen one!
            if ((headers_->content_length_status_ != content_length_status) ||
                ((headers_->content_length_status_ ==
                  BalsaHeadersEnums::VALID_CONTENT_LENGTH) &&
                 length != headers_->content_length_)) {
              last_error_ = BalsaFrameEnums::MULTIPLE_CONTENT_LENGTH_KEYS;
              parse_state_ = BalsaFrameEnums::PARSE_ERROR;
              visitor_->HandleHeaderError(this);
              return;
            }
            continue;
          } else {
            content_length_idx = i + 1;
            headers_->content_length_status_ = content_length_status;
            headers_->content_length_ = length;
            content_length_remaining_ = length;
          }

        }
      } else if (c == 't' || c == 'T') {
        if ((key_len == kTransferEncodingSize) &&
            0 == strncasecmp(key_begin, kTransferEncoding,
                             kTransferEncodingSize)) {
          if (transfer_encoding_idx != 0) {
            last_error_ = BalsaFrameEnums::MULTIPLE_TRANSFER_ENCODING_KEYS;
            parse_state_ = BalsaFrameEnums::PARSE_ERROR;
            visitor_->HandleHeaderError(this);
            return;
          }
          transfer_encoding_idx = i + 1;
        }
      } else if (i == 0 && (key_len == 0 || c == ' ')) {
        last_error_ = BalsaFrameEnums::INVALID_HEADER_FORMAT;
        parse_state_ = BalsaFrameEnums::PARSE_ERROR;
        visitor_->HandleHeaderError(this);
        return;
      }
    }
    if (headers_->transfer_encoding_is_chunked_) {
      headers_->content_length_ = 0;
      headers_->content_length_status_ = BalsaHeadersEnums::NO_CONTENT_LENGTH;
      content_length_remaining_ = 0;
    }
    if (transfer_encoding_idx != 0) {
      ProcessTransferEncodingLine(transfer_encoding_idx - 1);
    }
  }
}

void BalsaFrame::AssignParseStateAfterHeadersHaveBeenParsed() {
  // For responses, can't have a body if the request was a HEAD, or if it is
  // one of these response-codes.  rfc2616 section 4.3
  parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
  if (is_request_ ||
      !(request_was_head_ ||
        (headers_->parsed_response_code_ >= 100 &&
         headers_->parsed_response_code_ < 200) ||
        (headers_->parsed_response_code_ == 204) ||
        (headers_->parsed_response_code_ == 304))) {
    // Then we can have a body.
    if (headers_->transfer_encoding_is_chunked_) {
      // Note that
      // if ( Transfer-Encoding: chunked &&  Content-length: )
      // then Transfer-Encoding: chunked trumps.
      // This is as specified in the spec.
      // rfc2616 section 4.4.3
      parse_state_ = BalsaFrameEnums::READING_CHUNK_LENGTH;
    } else {
      // Errors parsing content-length definitely can cause
      // protocol errors/warnings
      switch (headers_->content_length_status_) {
        // If we have a content-length, and it is parsed
        // properly, there are two options.
        // 1) zero content, in which case the message is done, and
        // 2) nonzero content, in which case we have to
        //    consume the body.
        case BalsaHeadersEnums::VALID_CONTENT_LENGTH:
          if (headers_->content_length_ == 0) {
            parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
          } else {
            parse_state_ = BalsaFrameEnums::READING_CONTENT;
          }
          break;
        case BalsaHeadersEnums::CONTENT_LENGTH_OVERFLOW:
        case BalsaHeadersEnums::INVALID_CONTENT_LENGTH:
          // If there were characters left-over after parsing the
          // content length, we should flag an error and stop.
          parse_state_ = BalsaFrameEnums::PARSE_ERROR;
          last_error_ = BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH;
          visitor_->HandleHeaderError(this);
          break;
          // We can have: no transfer-encoding, no content length, and no
          // connection: close...
          // Unfortunately, this case doesn't seem to be covered in the spec.
          // We'll assume that the safest thing to do here is what the google
          // binaries before 2008 already do, which is to assume that
          // everything until the connection is closed is body.
        case BalsaHeadersEnums::NO_CONTENT_LENGTH:
          if (is_request_) {
            base::StringPiece method = headers_->request_method();
            // POSTs and PUTs should have a detectable body length.  If they
            // do not we consider it an error.
            if ((method.size() == 4 &&
                 strncmp(method.data(), "POST", 4) == 0) ||
                (method.size() == 3 &&
                 strncmp(method.data(), "PUT", 3) == 0)) {
              parse_state_ = BalsaFrameEnums::PARSE_ERROR;
              last_error_ =
                  BalsaFrameEnums::REQUIRED_BODY_BUT_NO_CONTENT_LENGTH;
              visitor_->HandleHeaderError(this);
              break;
            }
            parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
          } else {
            parse_state_ = BalsaFrameEnums::READING_UNTIL_CLOSE;
            last_error_ = BalsaFrameEnums::MAYBE_BODY_BUT_NO_CONTENT_LENGTH;
            visitor_->HandleHeaderWarning(this);
          }
          break;
          // The COV_NF_... statements here provide hints to the apparatus
          // which computes coverage reports/ratios that this code is never
          // intended to be executed, and should technically be impossible.
          // COV_NF_START
        default:
          LOG(FATAL) << "Saw a content_length_status: "
           << headers_->content_length_status_ << " which is unknown.";
          // COV_NF_END
      }
    }
  }
}

size_t BalsaFrame::ProcessHeaders(const char* message_start,
                                  size_t message_length) {
  const char* const original_message_start = message_start;
  const char* const message_end = message_start + message_length;
  const char* message_current = message_start;
  const char* checkpoint = message_start;

  if (message_length == 0) {
    goto bottom;
  }

  while (message_current < message_end) {
    size_t base_idx = headers_->GetReadableBytesFromHeaderStream();

    // Yes, we could use strchr (assuming null termination), or
    // memchr, but as it turns out that is slower than this tight loop
    // for the input that we see.
    if (!saw_non_newline_char_) {
      do {
        const char c = *message_current;
        if (c != '\r' && c != '\n') {
          if (c <= ' ') {
            parse_state_ = BalsaFrameEnums::PARSE_ERROR;
            last_error_ = BalsaFrameEnums::NO_REQUEST_LINE_IN_REQUEST;
            visitor_->HandleHeaderError(this);
            goto bottom;
          } else {
            saw_non_newline_char_ = true;
            checkpoint = message_start = message_current;
            goto read_real_message;
          }
        }
        ++message_current;
      } while (message_current < message_end);
      goto bottom;  // this is necessary to skip 'last_char_was_slash_r' checks
    } else {
 read_real_message:
      // Note that SSE2 can be enabled on certain piii platforms.
#if __SSE2__
      {
        const char* const message_end_m16 = message_end - 16;
        __m128i newlines = _mm_set1_epi8('\n');
        while (message_current < message_end_m16) {
          // What this does (using compiler intrinsics):
          //
          // Load 16 '\n's into an xmm register
          // Load 16 bytes of currennt message into an xmm register
          // Do byte-wise equals on those two xmm registers
          // Take the first bit of each byte, and put that into the first
          //   16 bits of a mask
          // If the mask is zero, no '\n' found. increment by 16 and try again
          // Else scan forward to find the first set bit.
          // Increment current by the index of the first set bit
          //   (ffs returns index of first set bit + 1)
          __m128i msg_bytes =
            _mm_loadu_si128(const_cast<__m128i *>(
                    reinterpret_cast<const __m128i *>(message_current)));
          __m128i newline_cmp = _mm_cmpeq_epi8(msg_bytes, newlines);
          int newline_msk = _mm_movemask_epi8(newline_cmp);
          if (newline_msk == 0) {
            message_current += 16;
            continue;
          }
          message_current += (ffs(newline_msk) - 1);
          const size_t relative_idx = message_current - message_start;
          const size_t message_current_idx = 1 + base_idx + relative_idx;
          lines_.push_back(std::make_pair(last_slash_n_idx_,
                                          message_current_idx));
          if (lines_.size() == 1) {
            headers_->WriteFromFramer(checkpoint,
                                      1 + message_current - checkpoint);
            checkpoint = message_current + 1;
            const char* begin = headers_->OriginalHeaderStreamBegin();
#if DEBUGFRAMER
          LOG(INFO) << "First line " << std::string(begin, lines_[0].second);
          LOG(INFO) << "is_request_: " << is_request_;
#endif
            ProcessFirstLine(begin, begin + lines_[0].second);
            if (parse_state_ == BalsaFrameEnums::MESSAGE_FULLY_READ)
              goto process_lines;
            else if (parse_state_ == BalsaFrameEnums::PARSE_ERROR)
              goto bottom;
          }
          const size_t chars_since_last_slash_n = (message_current_idx -
                                                   last_slash_n_idx_);
          last_slash_n_idx_ = message_current_idx;
          if (chars_since_last_slash_n > 2) {
            // We have a slash-n, but the last slash n was
            // more than 2 characters away from this. Thus, we know
            // that this cannot be an end-of-header.
            ++message_current;
            continue;
          }
          if ((chars_since_last_slash_n == 1) ||
              (((message_current > message_start) &&
                (*(message_current - 1) == '\r')) ||
               (last_char_was_slash_r_))) {
            goto process_lines;
          }
          ++message_current;
        }
      }
#endif  // __SSE2__
      while (message_current < message_end) {
        if (*message_current != '\n') {
          ++message_current;
          continue;
        }
        const size_t relative_idx = message_current - message_start;
        const size_t message_current_idx = 1 + base_idx + relative_idx;
        lines_.push_back(std::make_pair(last_slash_n_idx_,
                                        message_current_idx));
        if (lines_.size() == 1) {
          headers_->WriteFromFramer(checkpoint,
                                    1 + message_current - checkpoint);
          checkpoint = message_current + 1;
          const char* begin = headers_->OriginalHeaderStreamBegin();
#if DEBUGFRAMER
          LOG(INFO) << "First line " << std::string(begin, lines_[0].second);
          LOG(INFO) << "is_request_: " << is_request_;
#endif
          ProcessFirstLine(begin, begin + lines_[0].second);
          if (parse_state_ == BalsaFrameEnums::MESSAGE_FULLY_READ)
            goto process_lines;
          else if (parse_state_ == BalsaFrameEnums::PARSE_ERROR)
            goto bottom;
        }
        const size_t chars_since_last_slash_n = (message_current_idx -
                                                 last_slash_n_idx_);
        last_slash_n_idx_ = message_current_idx;
        if (chars_since_last_slash_n > 2) {
          // false positive.
          ++message_current;
          continue;
        }
        if ((chars_since_last_slash_n == 1) ||
            (((message_current > message_start) &&
              (*(message_current - 1) == '\r')) ||
             (last_char_was_slash_r_))) {
          goto process_lines;
        }
        ++message_current;
      }
    }
    continue;
 process_lines:
    ++message_current;
    DCHECK(message_current >= message_start);
    if (message_current > message_start) {
      headers_->WriteFromFramer(checkpoint, message_current - checkpoint);
    }

    // Check if we have exceeded maximum headers length
    // Although we check for this limit before and after we call this function
    // we check it here as well to make sure that in case the visitor changed
    // the max_header_length_ (for example after processing the first line)
    // we handle it gracefully.
    if (headers_->GetReadableBytesFromHeaderStream() > max_header_length_) {
      parse_state_ = BalsaFrameEnums::PARSE_ERROR;
      last_error_ = BalsaFrameEnums::HEADERS_TOO_LONG;
      visitor_->HandleHeaderError(this);
      goto bottom;
    }

    // Since we know that we won't be writing any more bytes of the header,
    // we tell that to the headers object. The headers object may make
    // more efficient allocation decisions when this is signaled.
    headers_->DoneWritingFromFramer();
    {
      const char* readable_ptr = NULL;
      size_t readable_size = 0;
      headers_->GetReadablePtrFromHeaderStream(&readable_ptr, &readable_size);
      visitor_->ProcessHeaderInput(readable_ptr, readable_size);
    }

    // Ok, now that we've written everything into our header buffer, it is
    // time to process the header lines (extract proper values for headers
    // which are important for framing).
    ProcessHeaderLines();
    if (parse_state_ == BalsaFrameEnums::PARSE_ERROR) {
      goto bottom;
    }
    AssignParseStateAfterHeadersHaveBeenParsed();
    if (parse_state_ == BalsaFrameEnums::PARSE_ERROR) {
      goto bottom;
    }
    visitor_->ProcessHeaders(*headers_);
    visitor_->HeaderDone();
    if (parse_state_ == BalsaFrameEnums::MESSAGE_FULLY_READ) {
      visitor_->MessageDone();
    }
    goto bottom;
  }
  // If we've gotten to here, it means that we've consumed all of the
  // available input. We need to record whether or not the last character we
  // saw was a '\r' so that a subsequent call to ProcessInput correctly finds
  // a header framing that is split across the two calls.
  last_char_was_slash_r_ = (*(message_end - 1) == '\r');
  DCHECK(message_current >= message_start);
  if (message_current > message_start) {
    headers_->WriteFromFramer(checkpoint, message_current - checkpoint);
  }
 bottom:
  return message_current - original_message_start;
}


size_t BalsaFrame::BytesSafeToSplice() const {
  switch (parse_state_) {
    case BalsaFrameEnums::READING_CHUNK_DATA:
      return chunk_length_remaining_;
    case BalsaFrameEnums::READING_UNTIL_CLOSE:
      return std::numeric_limits<size_t>::max();
    case BalsaFrameEnums::READING_CONTENT:
      return content_length_remaining_;
    default:
      return 0;
  }
}

void BalsaFrame::BytesSpliced(size_t bytes_spliced) {
  switch (parse_state_) {
    case BalsaFrameEnums::READING_CHUNK_DATA:
      if (chunk_length_remaining_ >= bytes_spliced) {
        chunk_length_remaining_ -= bytes_spliced;
        if (chunk_length_remaining_ == 0) {
          parse_state_ = BalsaFrameEnums::READING_CHUNK_TERM;
        }
        return;
      } else {
        last_error_ =
          BalsaFrameEnums::CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT;
        goto error_exit;
      }

    case BalsaFrameEnums::READING_UNTIL_CLOSE:
      return;

    case BalsaFrameEnums::READING_CONTENT:
      if (content_length_remaining_ >= bytes_spliced) {
        content_length_remaining_ -= bytes_spliced;
        if (content_length_remaining_ == 0) {
          parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
          visitor_->MessageDone();
        }
        return;
      } else {
        last_error_ =
          BalsaFrameEnums::CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT;
        goto error_exit;
      }

    default:
      last_error_ = BalsaFrameEnums::CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO;
      goto error_exit;
  }

 error_exit:
  parse_state_ = BalsaFrameEnums::PARSE_ERROR;
  visitor_->HandleBodyError(this);
};

// You may note that the state-machine contained within this function has both
// switch and goto labels for nearly the same thing. For instance, the
// following two labels refer to the same code block:
//   label_reading_chunk_data:
//   case BalsaFrameEnums::READING_CHUNK_DATA:
// The 'case' statement is required for the switch statement which occurs when
// ProcessInput is invoked. The goto label is required as the state-machine
// does not use a computed goto in any subsequent operations.
//
// Since several states exit the state machine for various reasons, there is
// also one label at the bottom of the function. When it is appropriate to
// return from the function, that part of the state machine instead issues a
// goto bottom; This results in less code duplication, and makes debugging
// easier (as you can add a statement to a section of code which is guaranteed
// to be invoked when the function is exiting.
size_t BalsaFrame::ProcessInput(const char* input, size_t size) {
  const char* current = input;
  const char* on_entry = current;
  const char* end = current + size;
#if DEBUGFRAMER
  LOG(INFO) << "\n=============="
            << BalsaFrameEnums::ParseStateToString(parse_state_)
            << "===============\n";
#endif  // DEBUGFRAMER

  DCHECK(headers_ != NULL);
  if (headers_ == NULL) return 0;

  if (parse_state_ == BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE) {
    const size_t header_length = headers_->GetReadableBytesFromHeaderStream();
    // Yes, we still have to check this here as the user can change the
    // max_header_length amount!
    // Also it is possible that we have reached the maximum allowed header size,
    // and we have more to consume (remember we are still inside
    // READING_HEADER_AND_FIRSTLINE) in which case we directly declare an error.
    if (header_length > max_header_length_ ||
        (header_length == max_header_length_ && size > 0)) {
      parse_state_ = BalsaFrameEnums::PARSE_ERROR;
      last_error_ = BalsaFrameEnums::HEADERS_TOO_LONG;
      visitor_->HandleHeaderError(this);
      goto bottom;
    }
    size_t bytes_to_process = max_header_length_ - header_length;
    if (bytes_to_process > size) {
      bytes_to_process = size;
    }
    current += ProcessHeaders(input, bytes_to_process);
    // If we are still reading headers check if we have crossed the headers
    // limit. Note that we check for >= as opposed to >. This is because if
    // header_length_after equals max_header_length_ and we are still in the
    // parse_state_  BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE we know for
    // sure that the headers limit will be crossed later on
    if (parse_state_ == BalsaFrameEnums::READING_HEADER_AND_FIRSTLINE) {
      // Note that headers_ is valid only if we are still reading headers.
      const size_t header_length_after =
          headers_->GetReadableBytesFromHeaderStream();
      if (header_length_after >= max_header_length_) {
        parse_state_ = BalsaFrameEnums::PARSE_ERROR;
        last_error_ = BalsaFrameEnums::HEADERS_TOO_LONG;
        visitor_->HandleHeaderError(this);
      }
    }
    goto bottom;
  } else if (parse_state_ == BalsaFrameEnums::MESSAGE_FULLY_READ ||
             parse_state_ == BalsaFrameEnums::PARSE_ERROR) {
    // Can do nothing more 'till we're reset.
    goto bottom;
  }

  while (current < end) {
    switch (parse_state_) {
 label_reading_chunk_length:
      case BalsaFrameEnums::READING_CHUNK_LENGTH:
        // In this state we read the chunk length.
        // Note that once we hit a character which is not in:
        // [0-9;A-Fa-f\n], we transition to a different state.
        //
        {
          // If we used strtol, etc, we'd have to buffer this line.
          // This is more annoying than simply doing the conversion
          // here. This code accounts for overflow.
          static const signed char buf[] = {
            // %0  %1  %2  %3  %4  %5  %6  %7  %8  \t  \n  %b  %c  \r  %e  %f
               -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1,
            // %10 %11 %12 %13 %14 %15 %16 %17 %18 %19 %1a %1b %1c %1d %1e %1f
               -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            // ' ' %21 %22 %23 %24 %25 %26 %27 %28 %29 %2a %2b %2c %2d %2e %2f
               -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            // %30 %31 %32 %33 %34 %35 %36 %37 %38 %39 %3a ';' %3c %3d %3e %3f
                0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -2, -1, -1, -1, -1,
            // %40 'A' 'B' 'C' 'D' 'E' 'F' %47 %48 %49 %4a %4b %4c %4d %4e %4f
               -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            // %50 %51 %52 %53 %54 %55 %56 %57 %58 %59 %5a %5b %5c %5d %5e %5f
               -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            // %60 'a' 'b' 'c' 'd' 'e' 'f' %67 %68 %69 %6a %6b %6c %6d %6e %6f
               -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            // %70 %71 %72 %73 %74 %75 %76 %77 %78 %79 %7a %7b %7c %7d %7e %7f
               -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
          };
          // valid cases:
          //  "09123\n"                      // -> 09123
          //  "09123\r\n"                    // -> 09123
          //  "09123  \n"                    // -> 09123
          //  "09123  \r\n"                  // -> 09123
          //  "09123  12312\n"               // -> 09123
          //  "09123  12312\r\n"             // -> 09123
          //  "09123; foo=bar\n"             // -> 09123
          //  "09123; foo=bar\r\n"           // -> 09123
          //  "FFFFFFFFFFFFFFFF\r\n"         // -> FFFFFFFFFFFFFFFF
          //  "FFFFFFFFFFFFFFFF 22\r\n"      // -> FFFFFFFFFFFFFFFF
          // invalid cases:
          // "[ \t]+[^\n]*\n"
          // "FFFFFFFFFFFFFFFFF\r\n"  (would overflow)
          // "\r\n"
          // "\n"
          while (current < end) {
            const char c = *current;
            ++current;
            const signed char addition = buf[static_cast<int>(c)];
            if (addition >= 0) {
              chunk_length_character_extracted_ = true;
              size_t length_x_16 = chunk_length_remaining_ * 16;
              const size_t kMaxDiv16 = std::numeric_limits<size_t>::max() / 16;
              if ((chunk_length_remaining_ > kMaxDiv16) ||
                  ((std::numeric_limits<size_t>::max() - length_x_16) <
                   static_cast<size_t>(addition))) {
                // overflow -- asked for a chunk-length greater than 2^64 - 1!!
                parse_state_ = BalsaFrameEnums::PARSE_ERROR;
                last_error_ = BalsaFrameEnums::CHUNK_LENGTH_OVERFLOW;
                visitor_->ProcessBodyInput(on_entry, current - on_entry);
                visitor_->HandleChunkingError(this);
                goto bottom;
              }
              chunk_length_remaining_ = length_x_16 + addition;
              continue;
            }

            if (!chunk_length_character_extracted_ || addition == -1) {
              // ^[0-9;A-Fa-f][ \t\n] -- was not matched, either because no
              // characters were converted, or an unexpected character was
              // seen.
              parse_state_ = BalsaFrameEnums::PARSE_ERROR;
              last_error_ = BalsaFrameEnums::INVALID_CHUNK_LENGTH;
              visitor_->ProcessBodyInput(on_entry, current - on_entry);
              visitor_->HandleChunkingError(this);
              goto bottom;
            }

            --current;
            parse_state_ = BalsaFrameEnums::READING_CHUNK_EXTENSION;
            visitor_->ProcessChunkLength(chunk_length_remaining_);
            goto label_reading_chunk_extension;
          }
        }
        visitor_->ProcessBodyInput(on_entry, current - on_entry);
        goto bottom;  // case BalsaFrameEnums::READING_CHUNK_LENGTH

 label_reading_chunk_extension:
      case BalsaFrameEnums::READING_CHUNK_EXTENSION:
        {
          // TODO(phython): Convert this scanning to be 16 bytes at a time if
          // there is data to be read.
          const char* extensions_start = current;
          size_t extensions_length = 0;
          while (current < end) {
            const char c = *current;
            if (c == '\r' || c == '\n') {
              extensions_length =
                  (extensions_start == current) ?
                  0 :
                  current - extensions_start - 1;
            }

            ++current;
            if (c == '\n') {
              chunk_length_character_extracted_ = false;
              visitor_->ProcessChunkExtensions(
                  extensions_start, extensions_length);
              if (chunk_length_remaining_ != 0) {
                parse_state_ = BalsaFrameEnums::READING_CHUNK_DATA;
                goto label_reading_chunk_data;
              }
              HeaderFramingFound('\n');
              parse_state_ = BalsaFrameEnums::READING_LAST_CHUNK_TERM;
              goto label_reading_last_chunk_term;
            }
          }
          visitor_->ProcessChunkExtensions(
              extensions_start, extensions_length);
        }

        visitor_->ProcessBodyInput(on_entry, current - on_entry);
        goto bottom;  // case BalsaFrameEnums::READING_CHUNK_EXTENSION

 label_reading_chunk_data:
      case BalsaFrameEnums::READING_CHUNK_DATA:
        while (current < end) {
          if (chunk_length_remaining_ == 0) {
            break;
          }
          // read in the chunk
          size_t bytes_remaining = end - current;
          size_t consumed_bytes = (chunk_length_remaining_ < bytes_remaining) ?
            chunk_length_remaining_ : bytes_remaining;
          const char* tmp_current = current + consumed_bytes;
          visitor_->ProcessBodyInput(on_entry, tmp_current - on_entry);
          visitor_->ProcessBodyData(current, consumed_bytes);
          on_entry = current = tmp_current;
          chunk_length_remaining_ -= consumed_bytes;
        }
        if (chunk_length_remaining_ == 0) {
          parse_state_ = BalsaFrameEnums::READING_CHUNK_TERM;
          goto label_reading_chunk_term;
        }
        visitor_->ProcessBodyInput(on_entry, current - on_entry);
        goto bottom;  // case BalsaFrameEnums::READING_CHUNK_DATA

 label_reading_chunk_term:
      case BalsaFrameEnums::READING_CHUNK_TERM:
        while (current < end) {
          const char c = *current;
          ++current;

          if (c == '\n') {
            parse_state_ = BalsaFrameEnums::READING_CHUNK_LENGTH;
            goto label_reading_chunk_length;
          }
        }
        visitor_->ProcessBodyInput(on_entry, current - on_entry);
        goto bottom;  // case BalsaFrameEnums::READING_CHUNK_TERM

 label_reading_last_chunk_term:
      case BalsaFrameEnums::READING_LAST_CHUNK_TERM:
        while (current < end) {
          const char c = *current;

          if (!HeaderFramingFound(c)) {
            // If not, however, since the spec only suggests that the
            // client SHOULD indicate the presence of trailers, we get to
            // *test* that they did or didn't.
            // If all of the bytes we've seen since:
            //   OPTIONAL_WS 0 OPTIONAL_STUFF CRLF
            // are either '\r', or '\n', then we can assume that we don't yet
            // know if we need to parse headers, or if the next byte will make
            // the HeaderFramingFound condition (above) true.
            if (HeaderFramingMayBeFound()) {
              // If true, then we have seen only characters '\r' or '\n'.
              ++current;

              // Lets try again! There is no state change here.
              continue;
            } else {
              // If (!HeaderFramingMayBeFound()), then we know that we must be
              // reading the first non CRLF character of a trailer.
              parse_state_ = BalsaFrameEnums::READING_TRAILER;
              visitor_->ProcessBodyInput(on_entry, current - on_entry);
              on_entry = current;
              goto label_reading_trailer;
            }
          } else {
            // If we've found a "\r\n\r\n", then the message
            // is done.
            ++current;
            parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
            visitor_->ProcessBodyInput(on_entry, current - on_entry);
            visitor_->MessageDone();
            goto bottom;
          }
          break;  // from while loop
        }
        visitor_->ProcessBodyInput(on_entry, current - on_entry);
        goto bottom;  // case BalsaFrameEnums::READING_LAST_CHUNK_TERM

 label_reading_trailer:
      case BalsaFrameEnums::READING_TRAILER:
        while (current < end) {
          const char c = *current;
          ++current;
          // TODO(fenix): If we ever care about trailers as part of framing,
          // deal with them here (see below for part of the 'solution')
          // if (LineFramingFound(c)) {
          // trailer_lines_.push_back(make_pair(start_of_line_,
          //                                   trailer_length_ - 1));
          // start_of_line_ = trailer_length_;
          // }
          if (HeaderFramingFound(c)) {
            // ProcessTrailers(visitor_, &trailers_);
            parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
            visitor_->ProcessTrailerInput(on_entry, current - on_entry);
            visitor_->MessageDone();
            goto bottom;
          }
        }
        visitor_->ProcessTrailerInput(on_entry, current - on_entry);
        break;  // case BalsaFrameEnums::READING_TRAILER

        // Note that there is no label:
        //   'label_reading_until_close'
        // here. This is because the state-machine exists immediately after
        // reading the headers instead of transitioning here (as it would
        // do if it was consuming all the data it could, all the time).
      case BalsaFrameEnums::READING_UNTIL_CLOSE:
        {
          const size_t bytes_remaining = end - current;
          if (bytes_remaining > 0) {
            visitor_->ProcessBodyInput(current, bytes_remaining);
            visitor_->ProcessBodyData(current, bytes_remaining);
            current += bytes_remaining;
          }
        }
        goto bottom;  // case BalsaFrameEnums::READING_UNTIL_CLOSE

        // label_reading_content:
      case BalsaFrameEnums::READING_CONTENT:
#if DEBUGFRAMER
        LOG(INFO) << "ReadingContent: " << content_length_remaining_;
#endif  // DEBUGFRAMER
        while (content_length_remaining_ && current < end) {
          // read in the content
          const size_t bytes_remaining = end - current;
          const size_t consumed_bytes =
            (content_length_remaining_ < bytes_remaining) ?
            content_length_remaining_ : bytes_remaining;
          visitor_->ProcessBodyInput(current, consumed_bytes);
          visitor_->ProcessBodyData(current, consumed_bytes);
          current += consumed_bytes;
          content_length_remaining_ -= consumed_bytes;
        }
        if (content_length_remaining_ == 0) {
          parse_state_ = BalsaFrameEnums::MESSAGE_FULLY_READ;
          visitor_->MessageDone();
        }
        goto bottom;  // case BalsaFrameEnums::READING_CONTENT

      default:
        // The state-machine should never be in a state that isn't handled
        // above.  This is a glaring logic error, and we should do something
        // drastic to ensure that this gets looked-at and fixed.
        LOG(FATAL) << "Unknown state: " << parse_state_  // COV_NF_LINE
          << " memory corruption?!";                     // COV_NF_LINE
    }
  }
 bottom:
#if DEBUGFRAMER
  LOG(INFO) << "\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n"
    << std::string(input, current)
    << "\n$$$$$$$$$$$$$$"
    << BalsaFrameEnums::ParseStateToString(parse_state_)
    << "$$$$$$$$$$$$$$$"
    << " consumed: " << (current - input);
  if (Error()) {
    LOG(INFO) << BalsaFrameEnums::ErrorCodeToString(ErrorCode());
  }
#endif  // DEBUGFRAMER
  return current - input;
}

}  // namespace net
