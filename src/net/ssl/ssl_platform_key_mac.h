// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_SSL_PLATFORM_KEY_MAC_H_
#define NET_SSL_SSL_PLATFORM_KEY_MAC_H_

#include <Security/SecBase.h>

#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"

namespace net {

class SSLPrivateKey;
class X509Certificate;

// Returns an SSLPrivateKey backed by the platform private key in |keychain|
// that corresponds to |certificate|'s public key. If |keychain| is nullptr, the
// user's default search list is used instead.
NET_EXPORT_PRIVATE scoped_refptr<SSLPrivateKey>
FetchClientCertPrivateKeyFromKeychain(const X509Certificate* certificate,
                                      SecKeychainRef keychain);

}  // namespace net

#endif  // NET_SSL_SSL_PLATFORM_KEY_MAC_H_
