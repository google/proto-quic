// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/hpack_string.h"

#include <utility>

#include "base/logging.h"

using base::StringPiece;
using std::string;

namespace net {

HpackString::HpackString(const char* data) : str_(data) {}
HpackString::HpackString(StringPiece str) : str_(str.as_string()) {}
HpackString::HpackString(string str) : str_(std::move(str)) {}
HpackString::HpackString(const HpackString& other) : str_(other.str_) {}
HpackString::~HpackString() {}

StringPiece HpackString::ToStringPiece() const {
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

HpackStringPair::HpackStringPair(const HpackString& name,
                                 const HpackString& value)
    : name(name), value(value) {
  DVLOG(3) << DebugString() << " ctor";
}

HpackStringPair::HpackStringPair(StringPiece name, StringPiece value)
    : name(name), value(value) {
  DVLOG(3) << DebugString() << " ctor";
}

HpackStringPair::~HpackStringPair() {
  DVLOG(3) << DebugString() << " dtor";
}

string HpackStringPair::DebugString() const {
  string debug_string("HpackStringPair(name=");
  debug_string.append(name.ToString());
  debug_string.append(", value=");
  debug_string.append(value.ToString());
  debug_string.append(")");
  return debug_string;
}

std::ostream& operator<<(std::ostream& os, const HpackStringPair& p) {
  os << p.DebugString();
  return os;
}

}  // namespace net
