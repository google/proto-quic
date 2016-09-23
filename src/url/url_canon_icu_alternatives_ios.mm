// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string.h>

#include "base/strings/string16.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "url/url_canon_internal.h"

namespace url {

// Only allow ASCII to avoid ICU dependency. Use NSString+IDN
// to convert non-ASCII URL prior to passing to API.
bool IDNToASCII(const base::char16* src, int src_len, CanonOutputW* output) {
  if (base::IsStringASCII(base::StringPiece16(src, src_len))) {
    output->Append(src, src_len);
    return true;
  }
  DCHECK(false) << "IDN URL support is not available.";
  return false;
}

}  // namespace url