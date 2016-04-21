// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_test_utils.h"

#include <cstring>
#include <memory>
#include <vector>

#include "base/base64.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/sys_byteorder.h"
#include "net/http/transport_security_state.h"
#include "net/ssl/ssl_info.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

using std::string;

string HexDumpWithMarks(const unsigned char* data,
                        int length,
                        const bool* marks,
                        int mark_length) {
  static const char kHexChars[] = "0123456789abcdef";
  static const int kColumns = 4;

  const int kSizeLimit = 1024;
  if (length > kSizeLimit || mark_length > kSizeLimit) {
    LOG(ERROR) << "Only dumping first " << kSizeLimit << " bytes.";
    length = std::min(length, kSizeLimit);
    mark_length = std::min(mark_length, kSizeLimit);
  }

  string hex;
  for (const unsigned char* row = data; length > 0;
       row += kColumns, length -= kColumns) {
    for (const unsigned char *p = row; p < row + 4; ++p) {
      if (p < row + length) {
        const bool mark =
            (marks && (p - data) < mark_length && marks[p - data]);
        hex += mark ? '*' : ' ';
        hex += kHexChars[(*p & 0xf0) >> 4];
        hex += kHexChars[*p & 0x0f];
        hex += mark ? '*' : ' ';
      } else {
        hex += "    ";
      }
    }
    hex = hex + "  ";

    for (const unsigned char* p = row; p < row + 4 && p < row + length; ++p) {
      hex += (*p >= 0x20 && *p <= 0x7f) ? (*p) : '.';
    }

    hex = hex + '\n';
  }
  return hex;
}

void CompareCharArraysWithHexError(const string& description,
                                   const unsigned char* actual,
                                   const int actual_len,
                                   const unsigned char* expected,
                                   const int expected_len) {
  const int min_len = std::min(actual_len, expected_len);
  const int max_len = std::max(actual_len, expected_len);
  std::unique_ptr<bool[]> marks(new bool[max_len]);
  bool identical = (actual_len == expected_len);
  for (int i = 0; i < min_len; ++i) {
    if (actual[i] != expected[i]) {
      marks[i] = true;
      identical = false;
    } else {
      marks[i] = false;
    }
  }
  for (int i = min_len; i < max_len; ++i) {
    marks[i] = true;
  }
  if (identical) return;
  ADD_FAILURE()
      << "Description:\n"
      << description
      << "\n\nExpected:\n"
      << HexDumpWithMarks(expected, expected_len, marks.get(), max_len)
      << "\nActual:\n"
      << HexDumpWithMarks(actual, actual_len, marks.get(), max_len);
}

void SetFrameFlags(SpdySerializedFrame* frame,
                   uint8_t flags,
                   SpdyMajorVersion spdy_version) {
  switch (spdy_version) {
    case SPDY3:
    case HTTP2:
      frame->data()[4] = flags;
      break;
    default:
      LOG(FATAL) << "Unsupported SPDY version.";
  }
}

void SetFrameLength(SpdySerializedFrame* frame,
                    size_t length,
                    SpdyMajorVersion spdy_version) {
  switch (spdy_version) {
    case SPDY3:
      CHECK_EQ(0u, length & ~kLengthMask);
      {
        int32_t wire_length = base::HostToNet32(length);
        // The length field in SPDY 3 is a 24-bit (3B) integer starting at
        // offset 5.
        memcpy(frame->data() + 5, reinterpret_cast<char*>(&wire_length) + 1, 3);
      }
      break;
    case HTTP2:
      CHECK_GT(1u<<14, length);
      {
        int32_t wire_length = base::HostToNet32(length);
        memcpy(frame->data(),
               reinterpret_cast<char*>(&wire_length) + 1,
               3);
      }
      break;
    default:
      LOG(FATAL) << "Unsupported SPDY version.";
  }
}

string a2b_hex(const char* hex_data) {
  std::vector<uint8_t> output;
  string result;
  if (base::HexStringToBytes(hex_data, &output))
    result.assign(reinterpret_cast<const char*>(&output[0]), output.size());
  return result;
}

HashValue GetTestHashValue(uint8_t label) {
  HashValue hash_value(HASH_VALUE_SHA256);
  memset(hash_value.data(), label, hash_value.size());
  return hash_value;
}

string GetTestPin(uint8_t label) {
  HashValue hash_value = GetTestHashValue(label);
  string base64;
  base::Base64Encode(base::StringPiece(
      reinterpret_cast<char*>(hash_value.data()), hash_value.size()), &base64);

  return string("pin-sha256=\"") + base64 + "\"";
}

void AddPin(TransportSecurityState* state,
            const string& host,
            uint8_t primary_label,
            uint8_t backup_label) {
  string primary_pin = GetTestPin(primary_label);
  string backup_pin = GetTestPin(backup_label);
  string header = "max-age = 10000; " + primary_pin + "; " + backup_pin;

  // Construct a fake SSLInfo that will pass AddHPKPHeader's checks.
  SSLInfo ssl_info;
  ssl_info.is_issued_by_known_root = true;
  ssl_info.public_key_hashes.push_back(GetTestHashValue(primary_label));
  EXPECT_TRUE(state->AddHPKPHeader(host, header, ssl_info));
}

void TestHeadersHandler::OnHeaderBlockStart() {
  block_.clear();
}

void TestHeadersHandler::OnHeader(base::StringPiece name,
                                  base::StringPiece value) {
  auto it = block_.find(name);
  if (it == block_.end()) {
    block_[name] = value;
  } else {
    string new_value = it->second.as_string();
    new_value.append((name == "cookie") ? "; " : string(1, '\0'));
    value.AppendToString(&new_value);
    block_.ReplaceOrAppendHeader(name, new_value);
  }
}

void TestHeadersHandler::OnHeaderBlockEnd(size_t header_bytes_parsed) {
  header_bytes_parsed_ = header_bytes_parsed;
}

}  // namespace test
}  // namespace net
