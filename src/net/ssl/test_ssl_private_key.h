// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_TEST_SSL_PLATFORM_KEY_H_
#define NET_SSL_TEST_SSL_PLATFORM_KEY_H_

#include <openssl/evp.h>

#include "base/memory/ref_counted.h"
#include "crypto/scoped_openssl_types.h"
#include "net/base/net_export.h"

namespace net {

class SSLPrivateKey;

// Returns a new SSLPrivateKey which uses |key| for signing operations or
// nullptr on error.
NET_EXPORT scoped_refptr<SSLPrivateKey> WrapOpenSSLPrivateKey(
    crypto::ScopedEVP_PKEY key);

}  // namespace net

#endif  // NET_SSL_TEST_SSL_PLATFORM_KEY_H_
