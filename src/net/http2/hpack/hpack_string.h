// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_HPACK_HPACK_STRING_H_
#define NET_HTTP2_HPACK_HPACK_STRING_H_

// HpackString is currently a very simple container for a string, but allows us
// to relatively easily experiment with alternate string storage mechanisms for
// handling strings to be encoded with HPACK, or decoded from HPACK, such as
// a ref-counted string.

#include <stddef.h>

#include <iosfwd>
#include <string>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

class NET_EXPORT_PRIVATE HpackString {
 public:
  explicit HpackString(const char* data);
  explicit HpackString(base::StringPiece str);
  explicit HpackString(std::string str);
  HpackString(const HpackString& other);

  // Not sure yet whether this move ctor is required/sensible.
  HpackString(HpackString&& other) = default;

  HpackString& operator=(const HpackString& other) = default;

  ~HpackString();

  size_t size() const { return str_.size(); }
  const std::string& ToString() const { return str_; }
  operator base::StringPiece() const;

  bool operator==(const HpackString& other) const;

  bool operator==(base::StringPiece str) const;

 private:
  std::string str_;
};

NET_EXPORT_PRIVATE bool operator==(base::StringPiece a, const HpackString& b);
NET_EXPORT_PRIVATE bool operator!=(base::StringPiece a, const HpackString& b);
NET_EXPORT_PRIVATE bool operator!=(const HpackString& a, const HpackString& b);
NET_EXPORT_PRIVATE bool operator!=(const HpackString& a, base::StringPiece b);
NET_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& out,
                                            const HpackString& v);

struct NET_EXPORT_PRIVATE HpackStringPair {
  HpackStringPair(const HpackString& name, const HpackString& value);
  HpackStringPair(base::StringPiece name, base::StringPiece value);
  ~HpackStringPair();

  // Returns the size of a header entry with this name and value, per the RFC:
  // http://httpwg.org/specs/rfc7541.html#calculating.table.size
  size_t size() const { return 32 + name.size() + value.size(); }

  std::string DebugString() const;

  HpackString name;
  HpackString value;
};

NET_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                            const HpackStringPair& p);

}  // namespace net

#endif  // NET_HTTP2_HPACK_HPACK_STRING_H_
