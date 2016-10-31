// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_OPENSSL_CLIENT_KEY_STORE_H_
#define NET_SSL_OPENSSL_CLIENT_KEY_STORE_H_

#include <map>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/singleton.h"
#include "net/base/net_export.h"
#include "third_party/boringssl/src/include/openssl/base.h"

namespace net {

class SSLPrivateKey;
class X509Certificate;

// OpenSSLClientKeyStore implements an in-memory store for client
// certificate private keys, because the platforms where OpenSSL is
// used do not provide a way to retrieve the private key of a known
// certificate.
//
// This class is not thread-safe and should only be used from the network
// thread.
class NET_EXPORT OpenSSLClientKeyStore {
 public:
  // Platforms must define this factory function as appropriate.
  static OpenSSLClientKeyStore* GetInstance();

  // Record the association between a certificate and its
  // private key. This method should be called _before_
  // FetchClientCertPrivateKey to ensure that the private key is returned
  // when it is called later. The association is recorded in memory
  // exclusively.
  // |cert| is a handle to a certificate object.
  // |private_key| is an SSLPrivateKey that corresponds to the certificate's
  // private key.
  // Returns false if an error occured.
  bool RecordClientCertPrivateKey(const X509Certificate* cert,
                                  scoped_refptr<SSLPrivateKey> key);

  // Given a certificate's |public_key|, return the corresponding private
  // key that has been recorded previously by RecordClientCertPrivateKey().
  // |cert| is a client certificate.
  // Returns its matching private key on success, NULL otherwise.
  scoped_refptr<SSLPrivateKey> FetchClientCertPrivateKey(
      const X509Certificate* cert);

  // Flush all recorded keys.
  void Flush();

 private:
  OpenSSLClientKeyStore();
  ~OpenSSLClientKeyStore();

  // Maps from the serialized SubjectPublicKeyInfo structure to the
  // corresponding private key.
  std::map<std::string, scoped_refptr<net::SSLPrivateKey>> key_map_;

  friend struct base::DefaultSingletonTraits<OpenSSLClientKeyStore>;

  DISALLOW_COPY_AND_ASSIGN(OpenSSLClientKeyStore);
};

}  // namespace net

#endif  // NET_SSL_OPENSSL_CLIENT_KEY_STORE_H_
