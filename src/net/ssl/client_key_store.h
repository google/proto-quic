// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_CLIENT_KEY_STORE_H_
#define NET_SSL_CLIENT_KEY_STORE_H_

#include <memory>
#include <vector>

#include "base/callback.h"
#include "base/lazy_instance.h"
#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "net/base/net_export.h"

namespace net {

class SSLPrivateKey;
class X509Certificate;

// TODO(rsleevi, davidben): Remove this once https://crbug.com/394131 is fixed.
// A certificate and key store that allows several external certificate
// providers to expose certificates and keys through this store. All currently
// provided certificates will be accessible through |FetchClientCertPrivateKey|.
// Methods of this singleton can be called from any thread.
class NET_EXPORT ClientKeyStore {
 public:
  class CertKeyProvider {
   public:
    // This can be called from any thread.
    virtual ~CertKeyProvider() {}

    // Obtains a handle to the certificate private key for |cert| and stores it
    // in |private_key|.
    // If the CertKeyProvider does not know about the |cert|, returns false. If
    // it knows about the certificate, but is unable to return the private key,
    // returns true and sets |*private_key| to nullptr.
    // This can be called from any thread.
    virtual bool GetCertificateKey(
        const X509Certificate& cert,
        scoped_refptr<SSLPrivateKey>* private_key) = 0;
  };

  static ClientKeyStore* GetInstance();

  // The |provider| will be accessed on any thread but no concurrent method
  // invocations will happen. |provider| must be valid until it is removed using
  // |RemoveProvider| or the store is destroyed.
  void AddProvider(CertKeyProvider* provider);

  void RemoveProvider(const CertKeyProvider* provider);

  // Given a |certificate|'s public key, return the corresponding private
  // key if any of the registered providers has a matching key.
  // Returns its matching private key on success, nullptr otherwise.
  scoped_refptr<SSLPrivateKey> FetchClientCertPrivateKey(
      const X509Certificate& certificate);

 private:
  friend struct base::LazyInstanceTraitsBase<ClientKeyStore>;

  ClientKeyStore();
  ~ClientKeyStore();

  base::Lock lock_;
  std::vector<CertKeyProvider*> providers_;

  DISALLOW_COPY_AND_ASSIGN(ClientKeyStore);
};

}  // namespace net

#endif  // NET_SSL_CLIENT_KEY_STORE_H_
