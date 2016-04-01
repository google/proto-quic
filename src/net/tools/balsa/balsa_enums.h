// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_BALSA_BALSA_ENUMS_H_
#define NET_TOOLS_BALSA_BALSA_ENUMS_H_

namespace net {

struct BalsaFrameEnums {
  enum ParseState {
    PARSE_ERROR,
    READING_HEADER_AND_FIRSTLINE,
    READING_CHUNK_LENGTH,
    READING_CHUNK_EXTENSION,
    READING_CHUNK_DATA,
    READING_CHUNK_TERM,
    READING_LAST_CHUNK_TERM,
    READING_TRAILER,
    READING_UNTIL_CLOSE,
    READING_CONTENT,
    MESSAGE_FULLY_READ,
    NUM_STATES,
  };

  enum ErrorCode {
#if defined(_WIN32)
    // On Windows, <WinError.h> defines the NO_ERROR macro as 0L, which
    // breaks the compilation of the "NO_ERROR = 0" line.
#undef NO_ERROR
#endif
    NO_ERROR = 0,  // A sentinel value for convenience, none of the callbacks
    //                should ever see this error code.
    // Header parsing errors
    // Note that adding one to many of the REQUEST errors yields the
    // appropriate RESPONSE error.
    // Particularly, when parsing the first line of a request or response,
    // there are three sequences of non-whitespace regardless of whether or
    // not it is a request or response. These are listed below, in order.
    //
    //        firstline_a     firstline_b    firstline_c
    //    REQ: method         request_uri    version
    //   RESP: version        statuscode     reason
    //
    // As you can see, the first token is the 'method' field for a request,
    // and 'version' field for a response. We call the first non whitespace
    // token firstline_a, the second firstline_b, and the third token
    // followed by [^\r\n]*) firstline_c.
    //
    // This organization is important, as it lets us determine the error code
    // to use without a branch based on is_response. Instead, we simply add
    // is_response to the response error code-- If is_response is true, then
    // we'll get the response error code, thanks to the fact that the error
    // code numbers are organized to ensure that response error codes always
    // precede request error codes.
    //                                                  | Triggered
    //                                                  | while processing
    //                                                  | this NONWS
    //                                                  | sequence...
    NO_STATUS_LINE_IN_RESPONSE,                      // |
    NO_REQUEST_LINE_IN_REQUEST,                      // |
    FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION,        // |  firstline_a
    FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD,          // |  firstline_a
    FAILED_TO_FIND_WS_AFTER_RESPONSE_STATUSCODE,     // |  firstline_b
    FAILED_TO_FIND_WS_AFTER_REQUEST_REQUEST_URI,     // |  firstline_b
    FAILED_TO_FIND_NL_AFTER_RESPONSE_REASON_PHRASE,  // |  firstline_c
    FAILED_TO_FIND_NL_AFTER_REQUEST_HTTP_VERSION,    // |  firstline_c

    FAILED_CONVERTING_STATUS_CODE_TO_INT,
    REQUEST_URI_TOO_LONG,  // Request URI greater than kMaxUrlLen.

    HEADERS_TOO_LONG,
    UNPARSABLE_CONTENT_LENGTH,
    // Warning: there may be a body but there was no content-length/chunked
    // encoding
    MAYBE_BODY_BUT_NO_CONTENT_LENGTH,

    // This is used if a body is required for a request.
    REQUIRED_BODY_BUT_NO_CONTENT_LENGTH,

    HEADER_MISSING_COLON,

    // Chunking errors
    INVALID_CHUNK_LENGTH,
    CHUNK_LENGTH_OVERFLOW,

    // Other errors.
    CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO,
    CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT,
    MULTIPLE_CONTENT_LENGTH_KEYS,
    MULTIPLE_TRANSFER_ENCODING_KEYS,
    UNKNOWN_TRANSFER_ENCODING,
    INVALID_HEADER_FORMAT,

    // A detected internal inconsistency was found.
    INTERNAL_LOGIC_ERROR,

    NUM_ERROR_CODES
  };
  static const char* ParseStateToString(ParseState error_code);
  static const char* ErrorCodeToString(ErrorCode error_code);
};

struct BalsaHeadersEnums {
  enum ContentLengthStatus {
    INVALID_CONTENT_LENGTH,
    CONTENT_LENGTH_OVERFLOW,
    NO_CONTENT_LENGTH,
    VALID_CONTENT_LENGTH,
  };
};

}  // namespace net

#endif  // NET_TOOLS_BALSA_BALSA_ENUMS_H_

