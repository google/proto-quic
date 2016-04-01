// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_BALSA_STRING_PIECE_UTILS_H_
#define NET_TOOLS_BALSA_STRING_PIECE_UTILS_H_

#include <stddef.h>

#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"

namespace net {

#if defined(COMPILER_MSVC)
struct StringPieceCaseCompare {
  static const size_t bucket_size = 4;

  size_t operator()(const base::StringPiece& sp) const {
    // based on __stl_string_hash in http://www.sgi.com/tech/stl/string
    size_t hash_val = 0;
    for (base::StringPiece::const_iterator it = sp.begin();
         it != sp.end(); ++it) {
      hash_val = 5 * hash_val + base::ToLowerASCII(*it);
    }
    return hash_val;
  }

  bool operator()(const base::StringPiece& sp1,
                  const base::StringPiece& sp2) const {
    size_t len1 = sp1.length();
    size_t len2 = sp2.length();
    bool sp1_shorter = len1 < len2;
    size_t len = sp1_shorter ? len1 : len2;

    int rv = 0;
    for (size_t i = 0; i < len; i++) {
      char sp1_lower = base::ToLowerASCII(sp1[i]);
      char sp2_lower = base::ToLowerASCII(sp2[i]);
      if (sp1_lower < sp2_lower) {
        rv = -1;
        break;
      }
      if (sp1_lower > sp2_lower) {
        rv = 1;
        break;
      }
    }

    if (rv == 0) {
      return sp1_shorter;
    }
    return rv < 0;
  }
};
#else  // COMPILER_MSVC
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
#endif  // COMPILER_MSVC

struct StringPieceCaseEqual {
  bool operator()(const base::StringPiece& piece1,
                  const base::StringPiece& piece2) const {
    return base::EqualsCaseInsensitiveASCII(piece1, piece2);
  }
};

}  // namespace net

#endif  // NET_TOOLS_BALSA_STRING_PIECE_UTILS_H_

