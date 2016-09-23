// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "base/strings/string16.h"
#include "base/strings/string_piece.h"
#include "net/base/net_string_util.h"

namespace net {

// This constant cannot be defined as const char[] because it is initialized
// by base::kCodepageLatin1 (which is const char[]) in net_string_util_icu.cc.
const char* const kCharsetLatin1 = "ISO-8859-1";

bool ConvertToUtf8(const std::string& text,
                   const char* charset,
                   std::string* output) {
  DCHECK(false) << "Not implemented yet.";
  return false;
}

bool ConvertToUtf8AndNormalize(const std::string& text,
                               const char* charset,
                               std::string* output) {
  DCHECK(false) << "Not implemented yet.";
  return false;
}

bool ConvertToUTF16(const std::string& text,
                    const char* charset,
                    base::string16* output) {
  DCHECK(false) << "Not implemented yet.";
  return false;
}

bool ConvertToUTF16WithSubstitutions(const std::string& text,
                                     const char* charset,
                                     base::string16* output) {
  DCHECK(false) << "Not implemented yet.";
  return false;
}

}  // namespace net