// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/hpack_string.h"

#include <utility>

using base::StringPiece;
using std::string;

namespace net {

HpackString::HpackString(const char* data) : str_(data) {}
HpackString::HpackString(StringPiece str) : str_(str.as_string()) {}
HpackString::HpackString(string str) : str_(std::move(str)) {}
HpackString::HpackString(const HpackString& other) : str_(other.str_) {}
HpackString::~HpackString() {}

HpackString::operator StringPiece() const {
  return str_;
}

bool HpackString::operator==(const HpackString& other) const {
  return str_ == other.str_;
}
bool HpackString::operator==(StringPiece str) const {
  return str == str_;
}

bool operator==(StringPiece a, const HpackString& b) {
  return b == a;
}
bool operator!=(StringPiece a, const HpackString& b) {
  return !(b == a);
}
bool operator!=(const HpackString& a, const HpackString& b) {
  return !(a == b);
}
bool operator!=(const HpackString& a, StringPiece b) {
  return !(a == b);
}
std::ostream& operator<<(std::ostream& out, const HpackString& v) {
  return out << v.ToString();
}

}  // namespace net
