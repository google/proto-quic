// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_BALSA_STRING_PIECE_UTILS_H_
#define NET_TOOLS_BALSA_STRING_PIECE_UTILS_H_

#include <stddef.h>

#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"

namespace net {

struct StringPieceCaseHash {
  size_t operator()(const base::StringPiece& sp) const {
    // based on __stl_string_hash in http://www.sgi.com/tech/stl/string
    size_t hash_val = 0;
    for (base::StringPiece::const_iterator it = sp.begin();
         it != sp.end(); ++it) {
      hash_val = 5 * hash_val + base::ToLowerASCII(*it);
    }
    return hash_val;
  }
};

struct StringPieceCaseEqual {
  bool operator()(const base::StringPiece& piece1,
                  const base::StringPiece& piece2) const {
    return base::EqualsCaseInsensitiveASCII(piece1, piece2);
  }
};

}  // namespace net

#endif  // NET_TOOLS_BALSA_STRING_PIECE_UTILS_H_

