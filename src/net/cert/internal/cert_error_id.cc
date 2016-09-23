// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/cert_error_id.h"

namespace net {

const char* CertErrorIdToDebugString(CertErrorId id) {
  // The CertErrorId is simply a pointer for a C-string literal.
  return reinterpret_cast<const char*>(id);
}

}  // namespace net
