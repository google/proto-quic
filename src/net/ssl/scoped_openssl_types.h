// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_SCOPED_OPENSSL_TYPES_H_
#define NET_SSL_SCOPED_OPENSSL_TYPES_H_

#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#include "crypto/scoped_openssl_types.h"

namespace net {

inline void FreeX509Stack(STACK_OF(X509)* ptr) {
  sk_X509_pop_free(ptr, X509_free);
}

inline void FreeX509NameStack(STACK_OF(X509_NAME)* ptr) {
  sk_X509_NAME_pop_free(ptr, X509_NAME_free);
}

using ScopedSSL = crypto::ScopedOpenSSL<SSL, SSL_free>;
using ScopedSSL_CTX = crypto::ScopedOpenSSL<SSL_CTX, SSL_CTX_free>;
using ScopedSSL_SESSION = crypto::ScopedOpenSSL<SSL_SESSION, SSL_SESSION_free>;
using ScopedX509 = crypto::ScopedOpenSSL<X509, X509_free>;
using ScopedX509_NAME = crypto::ScopedOpenSSL<X509_NAME, X509_NAME_free>;
using ScopedX509Stack = crypto::ScopedOpenSSL<STACK_OF(X509), FreeX509Stack>;
using ScopedX509NameStack =
    crypto::ScopedOpenSSL<STACK_OF(X509_NAME), FreeX509NameStack>;

}  // namespace net

#endif  // NET_SSL_SCOPED_OPENSSL_TYPES_H_
