// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_AUTO_CBB_H_
#define CRYPTO_AUTO_CBB_H_

#include <openssl/bytestring.h>

#include "base/macros.h"

namespace crypto {

// AutoCBB is a wrapper over OpenSSL's CBB type that automatically releases
// resources when going out of scope.
class AutoCBB {
 public:
  AutoCBB() { CBB_zero(&cbb_); }
  ~AutoCBB() { CBB_cleanup(&cbb_); }

  CBB* get() { return &cbb_; }

  void Reset() {
    CBB_cleanup(&cbb_);
    CBB_zero(&cbb_);
  }

 private:
  CBB cbb_;
  DISALLOW_COPY_AND_ASSIGN(AutoCBB);
};

}  // namespace crypto

#endif   // CRYPTO_AUTO_CBB_H_
