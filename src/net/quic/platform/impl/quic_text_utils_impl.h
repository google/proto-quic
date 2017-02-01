// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_PLATFORM_IMPL_QUIC_TEXT_UTILS_IMPL_H_
#define NET_QUIC_PLATFORM_IMPL_QUIC_TEXT_UTILS_IMPL_H_

#include <algorithm>

#include "base/base64.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/base/parse_number.h"

namespace net {

// google3 implementation of QuicTextUtils.
class QuicTextUtilsImpl {
 public:
  // Returns true of |data| starts with |prefix|, case sensitively.
  static bool StartsWith(base::StringPiece data, base::StringPiece prefix) {
    return base::StartsWith(data, prefix, base::CompareCase::SENSITIVE);
  }

  // Returns true of |data| ends with |suffix|, case insensitively.
  static bool EndsWithIgnoreCase(base::StringPiece data,
                                 base::StringPiece suffix) {
    return base::EndsWith(data, suffix, base::CompareCase::INSENSITIVE_ASCII);
  }

  // Returns a new std::string in which |data| has been converted to lower case.
  static std::string ToLower(base::StringPiece data) {
    return base::ToLowerASCII(data);
  }

  // Remove leading and trailing whitespace from |data|.
  static void RemoveLeadingAndTrailingWhitespace(base::StringPiece* data) {
    *data = base::TrimWhitespaceASCII(*data, base::TRIM_ALL);
  }

  // Returns true if |in| represents a valid uint64, and stores that value in
  // |out|.
  static bool StringToUint64(base::StringPiece in, uint64_t* out) {
    return base::StringToUint64(in, out);
  }

  // Returns true if |in| represents a valid int, and stores that value in
  // |out|.
  static bool StringToInt(base::StringPiece in, int* out) {
    return base::StringToInt(in, out);
  }

  // Returns true if |in| represents a valid uint32, and stores that value in
  // |out|.
  static bool StringToUint32(base::StringPiece in, uint32_t* out) {
    return ParseUint32(in, out, nullptr);
  }

  // Returns true if |in| represents a valid size_t, and stores that value in
  // |out|.
  static bool StringToSizeT(base::StringPiece in, size_t* out) {
    return base::StringToSizeT(in, out);
  }

  // Returns a new std::string representing |in|.
  static std::string Uint64ToString(uint64_t in) {
    return base::Uint64ToString(in);
  }

  // This converts |length| bytes of binary to a 2*|length|-character
  // hexadecimal representation.
  // Return value: 2*|length| characters of ASCII std::string.
  static std::string HexEncode(base::StringPiece data) {
    return base::ToLowerASCII(::base::HexEncode(data.data(), data.size()));
  }

  // Converts |data| from a hexadecimal ASCII string to a binary string
  // that is |data.length()/2| bytes long.
  static std::string HexDecode(base::StringPiece data) {
    if (data.empty())
      return "";
    std::vector<uint8_t> v;
    if (!base::HexStringToBytes(data.as_string(), &v))
      return "";
    std::string out;
    if (!v.empty())
      out.assign(reinterpret_cast<const char*>(&v[0]), v.size());
    return out;
  }

  // Base64 encodes with no padding |data_len| bytes of |data| into |output|.
  static void Base64Encode(const uint8_t* data,
                           size_t data_len,
                           std::string* output) {
    base::Base64Encode(
        std::string(reinterpret_cast<const char*>(data), data_len), output);
    // Remove padding.
    size_t len = output->size();
    if (len >= 2) {
      if ((*output)[len - 1] == '=') {
        len--;
        if ((*output)[len - 1] == '=') {
          len--;
        }
        output->resize(len);
      }
    }
  }

  // Returns a std::string containing hex and ASCII representations of |binary|,
  // side-by-side in the style of hexdump. Non-printable characters will be
  // printed as '.' in the ASCII output.
  // For example, given the input "Hello, QUIC!\01\02\03\04", returns:
  // "0x0000:  4865 6c6c 6f2c 2051 5549 4321 0102 0304  Hello,.QUIC!...."
  static std::string HexDump(base::StringPiece binary_input) {
    int offset = 0;
    const int kBytesPerLine = 16;  // Max bytes dumped per line
    const char* buf = binary_input.data();
    int bytes_remaining = binary_input.size();
    std::string s;  // our output
    const char* p = buf;
    while (bytes_remaining > 0) {
      const int line_bytes = std::min(bytes_remaining, kBytesPerLine);
      base::StringAppendF(&s, "0x%04x:  ", offset);  // Do the line header
      for (int i = 0; i < kBytesPerLine; ++i) {
        if (i < line_bytes) {
          base::StringAppendF(&s, "%02x", static_cast<unsigned char>(p[i]));
        } else {
          s += "  ";  // two-space filler instead of two-space hex digits
        }
        if (i % 2)
          s += ' ';
      }
      s += ' ';
      for (int i = 0; i < line_bytes; ++i) {  // Do the ASCII dump
        s += (p[i] > 32 && p[i] < 127) ? p[i] : '.';
      }

      bytes_remaining -= line_bytes;
      offset += line_bytes;
      p += line_bytes;
      s += '\n';
    }
    return s;
  }

  // Returns true if |data| contains any uppercase characters.
  static bool ContainsUpperCase(base::StringPiece data) {
    return std::any_of(data.begin(), data.end(), base::IsAsciiUpper<char>);
  }

  // Splits |data| into a vector of pieces delimited by |delim|.
  static std::vector<base::StringPiece> Split(base::StringPiece data,
                                              char delim) {
    return base::SplitStringPiece(data, base::StringPiece(&delim, 1),
                                  base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  }
};

}  // namespace net

#endif  // NET_QUIC_PLATFORM_IMPL_QUIC_TEXT_UTILS_IMPL_H_
