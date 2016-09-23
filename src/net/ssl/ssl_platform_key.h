// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_SSL_PLATFORM_KEY_H_
#define NET_SSL_SSL_PLATFORM_KEY_H_

#include <memory>

#include "base/lazy_instance.h"
#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"

namespace base {
class SequencedTaskRunner;
}

namespace net {

class SSLPrivateKey;
class X509Certificate;

// Looks up the private key from the platform key store corresponding to
// |certificate|'s public key and returns an SSLPrivateKey backed by the
// playform key.
NET_EXPORT scoped_refptr<SSLPrivateKey> FetchClientCertPrivateKey(
    X509Certificate* certificate);

}  // namespace net

#endif  // NET_SSL_SSL_PLATFORM_KEY_H_
